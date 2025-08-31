// Verification script to test io.Copy error handling in database proxies
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// checkFile verifies that io.Copy calls have proper error handling
func checkFile(filename string) ([]string, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Parse the Go source file (for future use if needed)
	// fset := token.NewFileSet()
	// _, err = parser.ParseFile(fset, filename, content, parser.ParseComments)
	// if err != nil {
	// 	return nil, err
	// }

	var issues []string
	
	// Check the actual source for io.Copy error handling patterns
	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineNum := 0
	inGoroutine := false
	var goroutineLines []string
	
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		
		// Track goroutine blocks
		if strings.Contains(line, "go func()") {
			inGoroutine = true
			goroutineLines = []string{}
		}
		
		if inGoroutine {
			goroutineLines = append(goroutineLines, line)
			
			// Check for io.Copy
			if strings.Contains(line, "io.Copy(") {
				// Look for error handling in the next few lines
				hasErrorHandling := false
				for _, gl := range goroutineLines {
					if strings.Contains(gl, "if err != nil") || 
					   strings.Contains(gl, "log.Printf") {
						hasErrorHandling = true
						break
					}
				}
				
				// Continue scanning a few more lines after io.Copy
				tempScanner := bufio.NewScanner(bytes.NewReader(content))
				tempLineNum := 0
				for tempScanner.Scan() {
					tempLineNum++
					if tempLineNum > lineNum && tempLineNum <= lineNum+5 {
						tempLine := tempScanner.Text()
						if strings.Contains(tempLine, "if err != nil") || 
						   strings.Contains(tempLine, "log.Printf") {
							hasErrorHandling = true
							break
						}
					}
				}
				
				if !hasErrorHandling {
					issues = append(issues, fmt.Sprintf("Line %d: io.Copy without error handling", lineNum))
				}
			}
			
			// Check for end of goroutine
			if strings.Contains(trimmed, "}()") {
				inGoroutine = false
				goroutineLines = []string{}
			}
		}
	}
	
	return issues, nil
}

// Walk the AST to find io.Copy calls
func findIOCopyCalls(file *ast.File) []token.Pos {
	var positions []token.Pos
	
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if ident, ok := sel.X.(*ast.Ident); ok {
					if ident.Name == "io" && sel.Sel.Name == "Copy" {
						positions = append(positions, x.Pos())
					}
				}
			}
		}
		return true
	})
	
	return positions
}

func main() {
	files := []string{
		"dbproxy/smtp.go",
		"dbproxy/redis.go", 
		"dbproxy/mssql.go",
		"dbproxy/mongodb.go",
	}
	
	fmt.Println("Verifying io.Copy error handling in database proxies...")
	fmt.Println("=" + strings.Repeat("=", 60))
	
	allPassed := true
	
	for _, file := range files {
		fullPath := filepath.Join("/root/repo", file)
		fmt.Printf("\nChecking %s:\n", file)
		
		issues, err := checkFile(fullPath)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
			allPassed = false
			continue
		}
		
		if len(issues) == 0 {
			fmt.Printf("  ✓ All io.Copy calls have proper error handling\n")
			
			// Additionally verify error logging is present
			content, _ := os.ReadFile(fullPath)
			if bytes.Contains(content, []byte("log.Printf")) && 
			   (bytes.Contains(content, []byte("error copying")) || 
			    bytes.Contains(content, []byte("proxy error")) ||
			    bytes.Contains(content, []byte("connection closed with error"))) {
				fmt.Printf("  ✓ Error logging is properly implemented\n")
			} else {
				fmt.Printf("  ⚠ Warning: Error logging may be incomplete\n")
			}
		} else {
			fmt.Printf("  ✗ Issues found:\n")
			for _, issue := range issues {
				fmt.Printf("    - %s\n", issue)
			}
			allPassed = false
		}
	}
	
	fmt.Println("\n" + strings.Repeat("=", 61))
	if allPassed {
		fmt.Println("✓ VERIFICATION PASSED: All io.Copy operations have proper error handling")
	} else {
		fmt.Println("✗ VERIFICATION FAILED: Some io.Copy operations lack proper error handling")
		os.Exit(1)
	}
}