package cloudflare

import (
	"context"
	"fmt"
	cf "github.com/cloudflare/cloudflare-go"
)

func GetZoneIds(ctx context.Context, client *cf.API) (zones map[string]string, err error) {
	zones = make(map[string]string)
	listZones, err := client.ListZones(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %v", err)
	}
	for _, zone := range listZones {
		zones[zone.Name] = zone.ID
	}
	return
}
