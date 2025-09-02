package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/livingdotone/vulnhound/internal/fetcher"
	"github.com/livingdotone/vulnhound/internal/filter"
	"github.com/livingdotone/vulnhound/internal/notifier"
	"github.com/spf13/viper"
)

type Config struct {
	DiscordToken string
	Channels     map[string]string
	DelaySeconds int
}

func LoadConfig() *Config {
	viper.SetConfigFile(".env")
	viper.SetConfigType("env")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Println("Warning: could not read .env file, relying on environment variables")
	}

	return &Config{
		DiscordToken: viper.GetString("DISCORD_BOT_TOKEN"),
		Channels: map[string]string{
			"web":     viper.GetString("CHANNEL_VULNS_WEB"),
			"linux":   viper.GetString("CHANNEL_VULNS_LINUX"),
			"windows": viper.GetString("CHANNEL_VULNS_WINDOWS"),
		},
	}
}

func main() {
	cfg := LoadConfig()

	if cfg.DiscordToken == "" {
		log.Fatal("DISCORD_BOT_TOKEN not set")
	}

	pubStart := time.Now().AddDate(0, 0, -7).Format(time.RFC3339)
	pubEnd := time.Now().Format(time.RFC3339)
	maxResults := viper.GetInt("MAX_RESULTS")
	if maxResults == 0 {
		maxResults = 50
	}

	cveQuery := fetcher.CVEQuery{
		PubStart:   pubStart,
		PubEnd:     pubEnd,
		MaxResults: maxResults,
	}

	cves, err := fetcher.FetchNVDCVEs(cveQuery)
	if err != nil {
		log.Fatal("Failed to fetch CVEs:", err)
	}

	log.Printf("Fetched %d CVEs", len(cves.Vulnerabilities))

	var infos []filter.CveInfo
	for i, vuln := range cves.Vulnerabilities {
		if len(vuln.Cve.Descriptions) == 0 {
			continue
		}

		desc := vuln.Cve.Descriptions[0].Value
		score := cves.GetScore(i)

		info := filter.BuildCveInfo(vuln.Cve.ID, desc, score)
		infos = append(infos, info)
	}

	if len(infos) == 0 {
		log.Println("No CVEs to send")
		return
	}

	dNotifier, err := notifier.New(cfg.DiscordToken, cfg.Channels, time.Duration(cfg.DelaySeconds))
	if err != nil {
		log.Fatal("Failed to init Discord notifier:", err)
	}
	defer dNotifier.Stop()

	log.Println("Sending CVEs to Discord...")
	dNotifier.SendCVEs(infos)

	log.Println("All CVEs sent successfully!")
}

func initDb() (*sql.DB, error) {
	dbPath := "../vulnhound.db"

	db, err := sql.Open("sqlite3", dbPath)

	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite DB: %w", err)
	}

	createTable := `
	CREATE TABLE IF NOT EXISTS sent_cves (
		cve_id TEXT PRIMARY KEY,
		sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);`

	if _, err := db.Exec(createTable); err != nil {
		return nil, fmt.Errorf("failed to create table: %w", err)
	}

	return db, nil
}
