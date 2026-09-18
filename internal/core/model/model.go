// Package model holds the data types shared across the scan/attack/report
// pipeline: endpoints discovered from the OpenAPI spec, check metadata, and
// the findings each stage reads and writes as JSON.
package model

// SchemaVersion is the current version of the findings/confirmed JSON file
// format written by the scan and attack stages.
//
// Version 2 added the coverage block; version 3 added the list of what was
// examined, which the block had been missing.
//
// Older files are rejected rather than read with the missing part empty,
// and the reason is the same each time: a file written before the scanner
// could account for something cannot be told apart from one where that
// something was empty. A v1 file read as "nothing failed" and a v2 file
// read as "no check reached a verdict" are both silently false, and both
// in the direction this block exists to prevent.
const SchemaVersion = 3
