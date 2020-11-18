package brightcloud

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
)

type infoDoc struct {
	XMLName  xml.Name     `xml:"bcap"`
	Response InfoResponse `xml:"response"`
}

// InfoResponse contains the web service response on a URI
type InfoResponse struct {
	Status    int    `xml:"status"`
	StatusMsg string `xml:"statusmsg"`
	URI       string `xml:"uri"`
	// Categories will only contain the ID and Confidence score
	// you will need to map the ID to the name and group retrieved via ListCategories
	Categories []Category `xml:"categories>cat"`
	// ReputationIndex is a security-related score is based on BrightCloud intelligence
	// on a given URL. 80-100 is trustworthy, 60-79 is low risk, 40-59 is moderate risk,
	// 20-39 is suspicious, and 0-19 is high risk.
	ReputationIndex int `xml:"bcri"`
	// All1Category means the subdomains of the URL are all of the same category
	All1Category int `xml:"a1cat"`
}

type heartBeatDoc struct {
	XMLName  xml.Name          `xml:"bcap"`
	Response HeartBeatResponse `xml:"response"`
}

// HeartBeatResponse from uris endpoint
type HeartBeatResponse struct {
	Status     int      `xml:"status"`
	StatusMsg  string   `xml:"statusmsg"`
	UpdateCDN  bool     `xml:"updatecdn"`
	UpdateRTU  bool     `xml:"updatertu"`
	UpdateTime string   `xml:"updatetime"`
	CDNListURI []string `xml:"cdnlist>uri"`
}

type categoriesDoc struct {
	XMLName  xml.Name       `xml:"bcap"`
	Response categoriesResp `xml:"response"`
}

type categoriesResp struct {
	Status     int        `xml:"status"`
	StatusMsg  string     `xml:"statusmsg"`
	Categories []Category `xml:"categories>cat"`
}

// Category represents a BrightCloud category
type Category struct {
	ID   int    `xml:"catid"`
	Name string `xml:"catname"`
	// Group can be: Security, Legal Liability, IT Resources, and Productivity.
	Group string `xml:"catgroup"`
	// Confidence is from 1-100, this is how confident they are about the BrightCloud classification.
	Confidence int `xml:"conf"`
}

// Service represents the BrightCloud web service
type Service struct {
	h *http.Client
	o *OAuth
}

// Info will get list of categories a URL is tagged in
func (s *Service) Info(reqURL string) (*InfoResponse, error) {
	// Validate URL
	validateURL := reqURL
	if len(reqURL) > 8 {
		if reqURL[0:8] != "https://" && reqURL[0:7] != "http://" {
			validateURL = "http://" + reqURL
		}
	} else {
		validateURL = "http://" + reqURL
	}
	_, err := url.ParseRequestURI(validateURL)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("http://thor.brightcloud.com/rest/uris/%v", reqURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	signedReq := s.o.SignRequest(req)
	resp, err := s.h.Do(signedReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	v := infoDoc{}
	d := xml.NewDecoder(resp.Body)
	err = d.Decode(&v)
	if err != nil {
		return nil, err
	}
	return &v.Response, nil
}

// HeartBeat web service status
func (s *Service) HeartBeat() (*HeartBeatResponse, error) {
	endpoint := "http://thor.brightcloud.com/rest/uris"
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	signedReq := s.o.SignRequest(req)
	resp, err := s.h.Do(signedReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	v := heartBeatDoc{}
	d := xml.NewDecoder(resp.Body)
	err = d.Decode(&v)
	if err != nil {
		return nil, err
	}

	return &v.Response, nil
}

// ListCategories will list available BrightCloud categories
func (s *Service) ListCategories() ([]Category, error) {
	endpoint := "http://thor.brightcloud.com/rest/uris/categories"
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	signedReq := s.o.SignRequest(req)
	resp, err := s.h.Do(signedReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%v: code %v", resp.Status, resp.StatusCode)
	}

	v := categoriesDoc{}
	d := xml.NewDecoder(resp.Body)
	err = d.Decode(&v)
	if err != nil {
		return nil, err
	}

	return v.Response.Categories, nil
}

// NewClient authorizes a new  brightcloud.Service using Oauth
func NewClient(key, secret string) *Service {
	s := new(Service)

	s.h = &http.Client{}
	s.o = NewOauthConsumer(key, secret)

	return s
}
