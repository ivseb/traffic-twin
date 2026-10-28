package config

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix prefixes every environment override. The variable name is the
// upper-cased YAML path joined with "_": admin.addr -> TT_CORE_ADMIN_ADDR,
// auth.session.idle_timeout -> TT_CORE_AUTH_SESSION_IDLE_TIMEOUT.
// Lists are comma-separated. Maps (role_mapping) are file-only.
const EnvPrefix = "TT_CORE_"

type envField struct {
	v reflect.Value
}

// envFields maps every overridable variable name (without prefix) to its field.
func envFields(cfg *Config) map[string]envField {
	out := map[string]envField{}
	var walk func(v reflect.Value, prefix string)
	walk = func(v reflect.Value, prefix string) {
		t := v.Type()
		for i := range t.NumField() {
			f := t.Field(i)
			fv := v.Field(i)
			if name, ok := f.Tag.Lookup("env"); ok {
				out[name] = envField{fv}
				continue
			}
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			name := prefix + strings.ToUpper(tag)
			if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Duration(0)) {
				walk(fv, name+"_")
				continue
			}
			if f.Type.Kind() == reflect.Map {
				continue
			}
			out[name] = envField{fv}
		}
	}
	walk(reflect.ValueOf(cfg).Elem(), "")
	return out
}

// EnvNames lists every supported override variable (with prefix).
func EnvNames() []string {
	var cfg Config
	var names []string
	for n := range envFields(&cfg) {
		names = append(names, EnvPrefix+n)
	}
	return names
}

// envAliases keeps older variable names working.
var envAliases = map[string]string{
	"TT_CORE_ADDR": "ADMIN_ADDR", // pre-config releases
}

func applyEnv(cfg *Config, environ []string) error {
	fields := envFields(cfg)
	var errs []error
	for _, kv := range environ {
		k, val, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, EnvPrefix) || k == EnvConfigPath {
			continue
		}
		name := strings.TrimPrefix(k, EnvPrefix)
		if alias, ok := envAliases[k]; ok {
			name = alias
		}
		f, known := fields[name]
		if !known {
			errs = append(errs, fmt.Errorf("config: unknown environment variable %s", k))
			continue
		}
		if err := setValue(f.v, val); err != nil {
			// The value is not echoed: it may be a secret.
			errs = append(errs, fmt.Errorf("config: %s: %v", k, err))
		}
	}
	return errors.Join(errs...)
}

func setValue(v reflect.Value, s string) error {
	switch {
	case v.Type() == reflect.TypeOf(ByteSize(0)):
		b, err := ParseByteSize(s)
		if err != nil {
			return err
		}
		v.SetInt(int64(b))
	case v.Type() == reflect.TypeOf(time.Duration(0)):
		d, err := time.ParseDuration(s)
		if err != nil {
			return errors.New("invalid duration")
		}
		v.SetInt(int64(d))
	case v.Kind() == reflect.String:
		v.SetString(s)
	case v.Kind() == reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return errors.New("invalid boolean")
		}
		v.SetBool(b)
	case v.Kind() == reflect.Int || v.Kind() == reflect.Int64:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return errors.New("invalid integer")
		}
		v.SetInt(n)
	case v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.String:
		var items []string
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				items = append(items, p)
			}
		}
		v.Set(reflect.ValueOf(items))
	default:
		return fmt.Errorf("unsupported type %s", v.Type())
	}
	return nil
}
