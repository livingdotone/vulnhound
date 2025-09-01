/*
Handles sending CVE alerts to Discord channels using discordgo.
It supports multiple categories and avoids message flood by spacing the messages.

Last Updated: 2025-09-01
*/

package notifier

import (
	"fmt"
	"time"

	"github.com/bwmarrin/discordgo"
	"github.com/livingdotone/vulnhound/internal/fetcher"
	"github.com/livingdotone/vulnhound/internal/filter"
)

type DiscordNotifier struct {
	Session  *discordgo.Session
	Channels map[string]string // key = CVE type, value = Discord channel ID
	Delay    time.Duration
}

func New(token string, channels map[string]string, delay time.Duration) (*DiscordNotifier, error) {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, fmt.Errorf("error creating Discord session: %w", err)
	}

	err = dg.Open()
	if err != nil {
		return nil, fmt.Errorf("error opening Discord session: %w", err)
	}

	return &DiscordNotifier{
		Session:  dg,
		Channels: channels,
		Delay:    delay,
	}, nil
}

func (n *DiscordNotifier) Close() {
	n.Session.Close()
}

func (n *DiscordNotifier) SendCVE(cve fetcher.CVE) error {
	cveType := filter.CVEType(cve.Description)
	channelID, ok := n.Channels[cveType]
	if !ok {
		return fmt.Errorf("no channel mapped for CVE type: %s", cveType)
	}

	_, err := n.Session.ChannelMessageSendEmbed(channelID, &discordgo.MessageEmbed{
		Title:       cve.ID,
		URL:         cve.URL,
		Description: cve.Description,
		Color:       16711680, // red
	})

	if err != nil {
		fmt.Errorf("error sending message to Discord: %w", err)
	}

	time.Sleep(n.Delay) // prevents flooding
	return nil
}

func (n *DiscordNotifier) SendCVEs(cves []fetcher.CVE) {
	categorized := make(map[string][]fetcher.CVE)
	for _, cve := range cves {
		t := filter.CVEType(cve.Description)
		categorized[t] = append(categorized[t], cve)
	}

	for cveType, list := range categorized {
		channelID, ok := n.Channels[cveType]
		if !ok {
			fmt.Printf("No channel mapped for type %s, skipping...\n", cveType)
			continue
		}

		for _, cve := range list {
			_, err := n.Session.ChannelMessageSendEmbed(channelID, &discordgo.MessageEmbed{
				Title:       cve.ID,
				URL:         cve.URL,
				Description: cve.Description,
				Color:       16711680,
			})
			if err != nil {
				fmt.Printf("Error sending CVE %s: %v\n", cve.ID, err)
			}
			time.Sleep(n.Delay)
		}
	}
}
