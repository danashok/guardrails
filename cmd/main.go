package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/ashokdan/guardrails/internal/config"
	"github.com/ashokdan/guardrails/internal/db"
	"github.com/ashokdan/guardrails/internal/routes"
)

// @title guardrails API
// @version 1.0
// @description LiteLLM generic_guardrail_api endpoint that evaluates PII and prompt-injection policies.
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name X-Guardrail-Auth-Key
func main() {
	logger, _ := zap.NewProduction()
	defer func() { _ = logger.Sync() }()

	cfg, err := config.NewConfig()
	if err != nil {
		logger.Fatal("Failed to load configuration", zap.Error(err))
	}

	database, err := db.InitDB(cfg.DBConfig)
	if err != nil {
		logger.Fatal("Failed to initialize database", zap.Error(err))
	}

	if err := db.AutoMigrate(database); err != nil {
		logger.Fatal("Failed to auto-migrate database", zap.Error(err))
	}

	router := gin.New()
	router.Use(gin.Recovery())
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Guardrail-Auth-Key", "X-Client-Id"},
		AllowCredentials: true,
		MaxAge:           86400,
	}))

	appRoutes, err := routes.NewRoutes(&routes.RouteOptions{
		Config: cfg,
		Logger: logger,
		DB:     database,
	})
	if err != nil {
		logger.Fatal("Failed to create application routes", zap.Error(err))
	}
	defer appRoutes.Shutdown()

	appRoutes.Bind(router)

	logger.Info("Starting HTTP server", zap.String("port", cfg.AppConfig.Port))
	if err := router.Run(":" + cfg.AppConfig.Port); err != nil {
		logger.Fatal("Failed to start server", zap.Error(err))
	}
}
