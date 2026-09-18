// Package model holds the data types shared across the scan/attack/report
// pipeline: endpoints discovered from the OpenAPI spec, check metadata, and
// the findings each stage reads and writes as JSON.
package model

// SchemaVersion is the current version of the findings/confirmed JSON file
// format written by the scan and attack stages.
//
// Version 2 added the coverage block. Version 1 files are rejected rather
// than read with an empty coverage: a file written before the scanner could
// account for what it failed to examine cannot be distinguished from one
// where nothing failed, and silently reading it as the latter is the exact
// confusion the block exists to end.
const SchemaVersion = 2
