package llm

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// Schema is the subset of the OpenAPI schema object that Vertex AI accepts as
// generationConfig.responseSchema. Only keywords Vertex supports are modelled;
// anything else (additionalProperties, oneOf, $ref, patternProperties, ...) is
// rejected by the API, so it cannot be expressed here by accident.
type Schema struct {
	Type        string             `json:"type"`
	Description string             `json:"description,omitempty"`
	Format      string             `json:"format,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Required    []string           `json:"required,omitempty"`
	// PropertyOrdering fixes the order the model writes object keys in; Vertex
	// otherwise orders them alphabetically, which separates a summary from
	// the content it summarises.
	PropertyOrdering []string `json:"propertyOrdering,omitempty"`
}

// Vertex AI schema type names.
const (
	TypeString  = "STRING"
	TypeNumber  = "NUMBER"
	TypeInteger = "INTEGER"
	TypeBoolean = "BOOLEAN"
	TypeArray   = "ARRAY"
	TypeObject  = "OBJECT"
)

// SchemaOf derives the response schema for the Go type T.
//
// Fields follow their `json` tag. A field without omitempty is required; one
// with omitempty is optional. Further struct tags refine a field:
//
//	desc:"text"          description shown to the model
//	enum:"a,b,c"         closed value set (for a slice, the set its items use)
//	format:"date-time"   string format
//
// Structs, pointers to structs, slices, strings, booleans, integers and floats
// are supported. Maps cannot be expressed in a Vertex schema (object keys are
// fixed), so a map field is an error: model it as a list of key/value
// structs instead.
func SchemaOf[T any]() (*Schema, error) {
	return schemaOfType(reflect.TypeFor[T]())
}

// MustSchemaOf is SchemaOf for package-level schemas of static types; it
// panics when the type cannot be expressed, which a test catches.
func MustSchemaOf[T any]() *Schema {
	s, err := SchemaOf[T]()
	if err != nil {
		panic(err)
	}
	return s
}

func schemaOfType(t reflect.Type) (*Schema, error) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return &Schema{Type: TypeString}, nil
	case reflect.Bool:
		return &Schema{Type: TypeBoolean}, nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return &Schema{Type: TypeInteger}, nil
	case reflect.Float32, reflect.Float64:
		return &Schema{Type: TypeNumber}, nil
	case reflect.Slice:
		items, err := schemaOfType(t.Elem())
		if err != nil {
			return nil, err
		}
		return &Schema{Type: TypeArray, Items: items}, nil
	case reflect.Struct:
		s := &Schema{Type: TypeObject, Properties: map[string]*Schema{}}
		if err := addStructFields(s, t); err != nil {
			return nil, fmt.Errorf("%s: %w", t.Name(), err)
		}
		if len(s.Properties) == 0 {
			return nil, fmt.Errorf("%s: object has no properties; Vertex rejects empty objects", t.Name())
		}
		return s, nil
	}
	return nil, fmt.Errorf("unsupported type %s in response schema", t)
}

func addStructFields(s *Schema, t reflect.Type) error {
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				if err := addStructFields(s, ft); err != nil {
					return err
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		fs, err := schemaOfType(f.Type)
		if err != nil {
			return fmt.Errorf("field %s: %w", name, err)
		}
		fs.Description = f.Tag.Get("desc")
		fs.Format = f.Tag.Get("format")
		if enum := f.Tag.Get("enum"); enum != "" {
			target := fs
			if fs.Type == TypeArray {
				target = fs.Items
			}
			if target.Type != TypeString {
				return fmt.Errorf("field %s: enum needs a string type", name)
			}
			target.Enum = strings.Split(enum, ",")
		}
		if _, dup := s.Properties[name]; dup {
			return fmt.Errorf("field %s: duplicate property", name)
		}
		s.Properties[name] = fs
		s.PropertyOrdering = append(s.PropertyOrdering, name)
		if !strings.Contains(","+opts+",", ",omitempty,") {
			s.Required = append(s.Required, name)
		}
	}
	return nil
}

// jsonSchema renders s as standard JSON Schema (lower-case type names), the
// form Ollama's `format` field takes.
func (s *Schema) jsonSchema() map[string]any {
	out := map[string]any{"type": strings.ToLower(s.Type)}
	if s.Description != "" {
		out["description"] = s.Description
	}
	if s.Format != "" {
		out["format"] = s.Format
	}
	if len(s.Enum) > 0 {
		out["enum"] = s.Enum
	}
	if s.Items != nil {
		out["items"] = s.Items.jsonSchema()
	}
	if len(s.Properties) > 0 {
		props := make(map[string]any, len(s.Properties))
		for name, p := range s.Properties {
			props[name] = p.jsonSchema()
		}
		out["properties"] = props
	}
	if len(s.Required) > 0 {
		out["required"] = s.Required
	}
	return out
}

// schemaKey is a stable digest input for s, used to tell requests apart.
func schemaKey(s *Schema) string {
	if s == nil {
		return ""
	}
	b, _ := json.Marshal(s)
	return string(b)
}
