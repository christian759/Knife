// knife/modules/wifi/geolocate.go
package wifi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type WiFiAccessPoint struct {
	MacAddress     string `json:"macAddress"`
	SignalStrength int    `json:"signalStrength"`
}

type GeoRequest struct {
	WifiAccessPoints []WiFiAccessPoint `json:"wifiAccessPoints"`
}

type GeoResponse struct {
	Location struct {
		Lat float64 `json:"lat"`
		Lng float64 `json:"lng"`
	} `json:"location"`
	Accuracy float64 `json:"accuracy"`
}

func Geolocate(macList []WiFiAccessPoint, apiKey string) (*GeoResponse, error) {
	requestBody, _ := json.Marshal(GeoRequest{WifiAccessPoints: macList})
	url := fmt.Sprintf("https://www.googleapis.com/geolocation/v1/geolocate?key=%s", apiKey)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var geo GeoResponse
	err = json.NewDecoder(resp.Body).Decode(&geo)
	if err != nil {
		return nil, err
	}
	return &geo, nil
}
