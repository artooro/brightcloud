# brightcloud

[![License](https://img.shields.io/github/license/artooro/brightcloud.svg)](https://github.com/artooro/brightcloud/blob/master/LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/artooro/brightcloud)](https://goreportcard.com/report/github.com/artooro/brightcloud)

A Go package to use the [BrightCloud web service](https://www.brightcloud.com/web-service).

## Example

```go
import "github.com/artooro/brightcloud"

client := brightcloud.New("consumerkey", "consumersecret")

// Get list of categories
categories, err := client.ListCategories()

// Lookup info on a URI
info, err := client.Info("github.com")
```
