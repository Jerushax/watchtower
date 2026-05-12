package detection

import (
    "os"
    "path/filepath"

    "gopkg.in/yaml.v3"
)

type Rule struct {
    Name        string   `yaml:"name"`
    Description string   `yaml:"description"`
    Severity    string   `yaml:"severity"`
    Score       int      `yaml:"score"`
    Matches     []string `yaml:"matches"`
}

func LoadRules(dir string) ([]*Rule, error) {

    var rules []*Rule

    files, err := os.ReadDir(dir)
    if err != nil {
        return nil, err
    }

    for _, file := range files {

        path := filepath.Join(dir, file.Name())

        data, err := os.ReadFile(path)
        if err != nil {
            continue
        }

        var rule Rule

        err = yaml.Unmarshal(data, &rule)
        if err != nil {
            continue
        }

        rules = append(rules, &rule)
    }

    return rules, nil
}
