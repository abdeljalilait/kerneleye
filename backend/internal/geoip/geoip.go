package geoip

import (
	"fmt"
	"log"
	"net/netip"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

type Service struct {
	cityDB    *maxminddb.Reader
	countryDB *maxminddb.Reader
	asnDB     *maxminddb.Reader
	mu        sync.RWMutex
}

type Record struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

func NewService(dbPath string) (*Service, error) {
	s := &Service{}

	// Try loading City DB
	cityPath := filepath.Join(dbPath, "GeoLite2-City.mmdb")
	cityDB, err := maxminddb.Open(cityPath)
	if err != nil {
		log.Printf("Warning: Failed to open GeoLite2-City: %v", err)
	} else {
		s.cityDB = cityDB
	}

	// Try loading ASN DB
	asnPath := filepath.Join(dbPath, "GeoLite2-ASN.mmdb")
	asnDB, err := maxminddb.Open(asnPath)
	if err != nil {
		log.Printf("Warning: Failed to open GeoLite2-ASN: %v", err)
	} else {
		s.asnDB = asnDB
	}

	return s, nil
}

func (s *Service) Close() {
	if s.cityDB != nil {
		s.cityDB.Close()
	}
	if s.asnDB != nil {
		s.asnDB.Close()
	}
}

func (s *Service) Lookup(ipStr string) (country, countryCode, city, isp, asn string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return "", "", "", "", "", err
	}

	if s.cityDB != nil {
		var record struct {
			Country struct {
				ISOCode string            `maxminddb:"iso_code"`
				Names   map[string]string `maxminddb:"names"`
			} `maxminddb:"country"`
			City struct {
				Names map[string]string `maxminddb:"names"`
			} `maxminddb:"city"`
		}

		if err := s.cityDB.Lookup(ip).Decode(&record); err == nil {
			country = record.Country.Names["en"]
			countryCode = record.Country.ISOCode
			city = record.City.Names["en"]
		}
	}

	if s.asnDB != nil {
		var record struct {
			AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
			AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		}
		if err := s.asnDB.Lookup(ip).Decode(&record); err == nil {
			isp = record.AutonomousSystemOrganization
			if record.AutonomousSystemNumber > 0 {
				asn = fmt.Sprintf("AS%d", record.AutonomousSystemNumber)
			}
		}
	}

	return country, countryCode, city, isp, asn, nil
}
