package main

import (
	"github.com/labstack/echo"
	"net/http"
)

var hardcodedSPIFFEMasks = []string{"spiffe://mydomain/*"}

type _strValue struct {
	Locked bool
	Value  string
}

type serverPolicy struct {
	CertificateAuthority _strValue
	CsrGeneration        _strValue
	KeyGeneration        _strValue
	KeyPair              struct {
		KeyAlgorithm _strValue
		KeySize      struct {
			Locked bool
			Value  int
		}
		EllipticCurve struct {
			Locked bool
			Value  string
		}
	}
	ManagementType _strValue

	PrivateKeyReuseAllowed  bool
	SubjAltNameDnsAllowed   bool
	SubjAltNameEmailAllowed bool
	SubjAltNameIpAllowed    bool
	SubjAltNameUpnAllowed   bool
	SubjAltNameUriAllowed   bool
	Subject                 struct {
		City               _strValue
		Country            _strValue
		Organization       _strValue
		OrganizationalUnit struct {
			Locked bool
			Values []string
		}

		State _strValue
	}
	UniqueSubjectEnforced bool
	WhitelistedDomains    []string
	WildcardsAllowed      bool
	SPIFFEMasks           []string
}

func fakePolicy(c echo.Context) error {
	r := serverPolicy{
		SPIFFEMasks: hardcodedSPIFFEMasks,
	}
	return c.JSON(http.StatusOK, &r)
}
