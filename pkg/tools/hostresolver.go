// Package pkg hostresolver.go this GO is to resolve host to their IP
package pkg

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// this is our logging function to keep track of the IPS?
type HostResolverResult struct{}
