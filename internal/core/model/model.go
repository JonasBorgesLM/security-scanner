// Package model holds the data types shared across the scan/attack/report
// pipeline: endpoints discovered from the OpenAPI spec, check metadata, and
// the findings each stage reads and writes as JSON.
package model

// SchemaVersion is the current version of the findings/confirmed JSON file
// format written by the scan and attack stages.
const SchemaVersion = 1
