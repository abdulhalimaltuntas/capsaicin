package reporting

import (
	"encoding/json"
	"os"

	"github.com/capsaicin/scanner/internal/scanner"
)

func SaveJSON(results []scanner.Result, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}