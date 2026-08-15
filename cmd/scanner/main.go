package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		runScan(os.Args[2:])
	case "attack":
		runAttack(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `scanner - security scanner for lab APIs

Usage:
  scanner scan   --spec openapi.yaml --config config.yaml --out findings.json
  scanner attack --in findings.json  --config config.yaml --out confirmed.json
  scanner report --in confirmed.json --out report.html`)
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	spec := fs.String("spec", "", "path to OpenAPI spec")
	config := fs.String("config", "", "path to config.yaml")
	out := fs.String("out", "findings.json", "path to output findings JSON")
	fs.Parse(args)

	_ = spec
	_ = config
	_ = out

	fmt.Println("scan: not implemented")
}

func runAttack(args []string) {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	in := fs.String("in", "", "path to findings.json")
	config := fs.String("config", "", "path to config.yaml")
	out := fs.String("out", "confirmed.json", "path to output confirmed JSON")
	fs.Parse(args)

	_ = in
	_ = config
	_ = out

	fmt.Println("attack: not implemented")
}

func runReport(args []string) {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	in := fs.String("in", "", "path to confirmed.json")
	out := fs.String("out", "report.html", "path to output report HTML")
	fs.Parse(args)

	_ = in
	_ = out

	fmt.Println("report: not implemented")
}
