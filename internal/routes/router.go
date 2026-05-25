package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/ashokdan/guardrails/internal/config"
	"github.com/ashokdan/guardrails/internal/controller"
	"github.com/ashokdan/guardrails/internal/engine"
	"github.com/ashokdan/guardrails/internal/middleware"
	"github.com/ashokdan/guardrails/internal/repository"
	"github.com/ashokdan/guardrails/internal/service"
)

type RouteOptions struct {
	Config *config.Config
	Logger *zap.Logger
	DB     *gorm.DB
}

type Routes struct {
	opts                *RouteOptions
	guardrailController *controller.GuardrailController
	auditService        service.IGuardrailEventService
}

func NewRoutes(opts *RouteOptions) (*Routes, error) {
	repo := repository.NewHandler(opts.DB)

	engine.InitToolChecks(
		opts.Config.AppConfig.RestrictedTerms,
		opts.Config.AppConfig.AllowedReadRoots,
		opts.Config.AppConfig.AllowedWriteRoots,
	)

	piiSvc := service.NewPIIAndToolCheckService(opts.Config.AppConfig.MaxConcurrent)
	promptSvc := service.NewPromptInjectionService(opts.Config.AppConfig.MaxConcurrent)

	authzSvc := service.NewAuthorizationService(
		repo.AuthorizedIP,
		opts.Logger,
		opts.Config.AppConfig.AuthzCacheTTL,
	)

	auditSvc := service.NewGuardrailEventService(
		repo.GuardrailEvent,
		opts.Logger,
		opts.Config.AppConfig.AuditEnabled,
		opts.Config.AppConfig.AuditWorkers,
		opts.Config.AppConfig.AuditBuffer,
	)

	gc := controller.NewGuardrailController(piiSvc, promptSvc, authzSvc, auditSvc, opts.Logger)

	return &Routes{
		opts:                opts,
		guardrailController: gc,
		auditService:        auditSvc,
	}, nil
}

func (r *Routes) Bind(router *gin.Engine) {
	router.GET("/health/liveliness", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	bindGuardrailRoutes(router, r.opts, r.guardrailController)
}

func (r *Routes) Shutdown() {
	r.auditService.Shutdown()
}

// MaxBodyBytesMiddleware caps inbound bodies to defend against DoS via giant payloads.
func MaxBodyBytesMiddleware(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}

func bindGuardrailRoutes(router *gin.Engine, opts *RouteOptions, gc *controller.GuardrailController) {
	beta := router.Group("/beta")
	beta.Use(MaxBodyBytesMiddleware(opts.Config.AppConfig.MaxBodyBytes))
	beta.Use(middleware.AuthMiddleware(opts.Config.AppConfig.GuardrailKey))
	beta.POST("/litellm_basic_guardrail_api", gc.Evaluate)
}
