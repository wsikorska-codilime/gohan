// Copyright (C) 2015 NTT Innovation Institute, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package schema

import (
	"fmt"

	"github.com/cloudwan/gohan/util"
	"github.com/xeipuuv/gojsonschema"
	"strings"
)

//Schema type for defining data type
type Schema struct {
	ID, Plural, Title, Description string
	Type                           string
	Extends                        []string
	ParentSchema                   *Schema
	Parent                         string
	NamespaceID                    string
	Namespace                      *Namespace
	Metadata                       map[string]interface{}
	Prefix                         string
	Properties                     []Property
	JSONSchema                     map[string]interface{}
	JSONSchemaOnCreate             map[string]interface{}
	JSONSchemaOnUpdate             map[string]interface{}
	Actions                        []Action
	Singular                       string
	URL                            string
	URLWithParents                 string
	RawData                        interface{}
	IsolationLevel                 map[string]interface{}
	OnParentDeleteCascade          bool
}

const (
	abstract string = "abstract"
)

//Schemas is a list of schema
//This struct is needed for json decode
type Schemas struct {
	Schemas []*Schema
}

//Map is a map of schema
type Map map[string]*Schema

type typeAssertionError struct {
	field string
}

func (e *typeAssertionError) Error() string {
	return fmt.Sprintf("Type Assertion Error: invalid schema %v field", e.field)
}

//NewSchema is a constructor for a schema
func NewSchema(id, plural, title, description, singular string) *Schema {
	schema := &Schema{
		ID:          id,
		Title:       title,
		Plural:      plural,
		Description: description,
		Singular:    singular,
		Extends:     []string{},
	}
	return schema
}

//NewSchemaFromObj is a constructor for a schema by obj
func NewSchemaFromObj(rawTypeData interface{}) (*Schema, error) {
	typeData := rawTypeData.(map[string]interface{})

	metaschema, ok := GetManager().Schema("schema")
	if ok {
		err := metaschema.Validate(metaschema.JSONSchema, typeData)
		if err != nil {
			return nil, err
		}
	}

	id := util.MaybeString(typeData["id"])
	if id == "" {
		return nil, &typeAssertionError{"id"}
	}
	plural := util.MaybeString(typeData["plural"])
	if plural == "" {
		return nil, &typeAssertionError{"plural"}
	}
	title := util.MaybeString(typeData["title"])
	if title == "" {
		return nil, &typeAssertionError{"title"}
	}
	description := util.MaybeString(typeData["description"])
	if description == "" {
		return nil, &typeAssertionError{"description"}
	}
	singular := util.MaybeString(typeData["singular"])
	if singular == "" {
		return nil, &typeAssertionError{"singular"}
	}

	schema := NewSchema(id, plural, title, description, singular)

	schema.Prefix = util.MaybeString(typeData["prefix"])
	schema.URL = util.MaybeString(typeData["url"])
	schema.Type = util.MaybeString(typeData["type"])
	schema.Parent = util.MaybeString(typeData["parent"])
	schema.OnParentDeleteCascade, _ = typeData["on_parent_delete_cascade"].(bool)
	schema.NamespaceID = util.MaybeString(typeData["namespace"])
	schema.IsolationLevel = util.MaybeMap(typeData["isolation_level"])
	jsonSchema, ok := typeData["schema"].(map[string]interface{})
	if !ok {
		return nil, &typeAssertionError{"schema"}
	}
	schema.JSONSchema = jsonSchema

	schema.Metadata = util.MaybeMap(typeData["metadata"])
	schema.Extends = util.MaybeStringList(typeData["extends"])

	actions := util.MaybeMap(typeData["actions"])
	schema.Actions = []Action{}
	for actionID, actionBody := range actions {
		action, err := NewActionFromObject(actionID, actionBody)
		if err != nil {
			return nil, err
		}
		schema.Actions = append(schema.Actions, action)
	}

	if err := schema.Init(); err != nil {
		return nil, err
	}
	return schema, nil
}

// Init initializes schema
func (schema *Schema) Init() error {
	if schema.IsAbstract() {
		return nil
	}
	jsonSchema := schema.JSONSchema
	parent := schema.Parent

	required := util.MaybeStringList(jsonSchema["required"])
	properties := util.MaybeMap(jsonSchema["properties"])
	propertiesOrder := util.MaybeStringList(jsonSchema["propertiesOrder"])
	if parent != "" && properties[FormatParentID(parent)] == nil {
		properties[FormatParentID(parent)] = getParentPropertyObj(parent, parent)
		propertiesOrder = append(propertiesOrder, FormatParentID(parent))
		required = append(required, FormatParentID(parent))
	}

	jsonSchema["required"] = required

	schema.JSONSchemaOnCreate = filterSchemaByPermission(jsonSchema, "create")
	schema.JSONSchemaOnUpdate = filterSchemaByPermission(jsonSchema, "update")

	schema.Properties = []Property{}
	for key := range properties {
		if !util.ContainsString(propertiesOrder, key) {
			propertiesOrder = append(propertiesOrder, key)
		}
	}
	jsonSchema["propertiesOrder"] = propertiesOrder

	for _, id := range propertiesOrder {
		property, ok := properties[id]
		if !ok {
			continue
		}
		propertyRequired := util.ContainsString(required, id)
		propertyObj, err := NewPropertyFromObj(id, property, propertyRequired)
		if err != nil {
			return fmt.Errorf("Invalid schema: Properties is missing %v", err)
		}
		schema.Properties = append(schema.Properties, *propertyObj)
	}
	return nil
}

// IsAbstract checks if this schema is abstract or not
func (schema *Schema) IsAbstract() bool {
	return schema.Type == abstract
}

// ParentID returns parent property ID
func (schema *Schema) ParentID() string {
	if schema.Parent == "" {
		return ""
	}
	return FormatParentID(schema.Parent)
}

// GetSingleURL returns a URL for access to a single schema object
func (schema *Schema) GetSingleURL() string {
	return fmt.Sprintf("%s/:id", schema.URL)
}

// GetActionURL returns a URL for access to resources actions
func (schema *Schema) GetActionURL(path string) string {
	return schema.URL + path
}

// GetPluralURL returns a URL for access to all schema objects
func (schema *Schema) GetPluralURL() string {
	return schema.URL
}

// GetSingleURLWithParents returns a URL for access to a single schema object
func (schema *Schema) GetSingleURLWithParents() string {
	return fmt.Sprintf("%s/:id", schema.URLWithParents)
}

// GetPluralURLWithParents returns a URL for access to all schema objects
func (schema *Schema) GetPluralURLWithParents() string {
	return schema.URLWithParents
}

// GetDbTableName returns a name of DB table used for storing schema instances
func (schema *Schema) GetDbTableName() string {
	return schema.ID + "s"
}

// GetParentURL returns Parent URL
func (schema *Schema) GetParentURL() string {
	if schema.Parent == "" {
		return ""
	}

	return schema.ParentSchema.GetParentURL() + "/" + schema.ParentSchema.Plural + "/:" + schema.Parent
}

func filterSchemaByPermission(schema map[string]interface{}, permission string) map[string]interface{} {
	filteredSchema := map[string]interface{}{"type": "object"}
	filteredProperties := map[string]map[string]interface{}{}
	for id, property := range util.MaybeMap(schema["properties"]) {
		propertyMap := util.MaybeMap(property)
		allowedList := util.MaybeStringList(propertyMap["permission"])
		for _, allowed := range allowedList {
			if allowed == permission {
				filteredProperties[id] = propertyMap
			}
		}
	}
	filteredSchema["properties"] = filteredProperties
	filteredSchema["required"] = util.MaybeStringList(schema["required"])
	if permission != "create" {
		// required property is used on only create event
		filteredSchema["required"] = []string{}
	}
	filteredSchema["additionalProperties"] = false
	return filteredSchema
}

func getParentPropertyObj(title, parent string) map[string]interface{} {
	return map[string]interface{}{
		"type":        "string",
		"relation":    parent,
		"title":       title,
		"description": "parent object",
		"unique":      false,
		"permission":  []interface{}{"create"},
	}
}

//ValidateOnCreate validates json object using jsoncschema on object creation
func (schema *Schema) ValidateOnCreate(object interface{}) error {
	return schema.Validate(schema.JSONSchemaOnCreate, object)
}

//ValidateOnUpdate validates json object using jsoncschema on object update
func (schema *Schema) ValidateOnUpdate(object interface{}) error {
	return schema.Validate(schema.JSONSchemaOnUpdate, object)
}

//Validate validates json object using jsoncschema
func (schema *Schema) Validate(jsonSchema interface{}, object interface{}) error {
	schemaLoader := gojsonschema.NewGoLoader(jsonSchema)
	documentLoader := gojsonschema.NewGoLoader(object)
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return err
	}
	if result.Valid() {
		return nil
	}
	errDescription := "Json validation error:"
	for _, err := range result.Errors() {
		errDescription += fmt.Sprintf("\n\t%v,", err)
	}
	return fmt.Errorf(errDescription)
}

//SetParentSchema sets parent schema
func (schema *Schema) SetParentSchema(parentSchema *Schema) {
	schema.ParentSchema = parentSchema
}

// SetNamespace sets namespace
func (schema *Schema) SetNamespace(namespace *Namespace) {
	schema.Namespace = namespace
}

//ParentSchemaPropertyID get property id for parent relation
func (schema *Schema) ParentSchemaPropertyID() string {
	if schema.Parent == "" {
		return ""
	}
	return FormatParentID(schema.Parent)
}

//GetPropertyByID get a property object using ID
func (schema *Schema) GetPropertyByID(id string) (*Property, error) {
	for _, p := range schema.Properties {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, fmt.Errorf("Property with ID %s not found", id)
}

//StateVersioning whether resources created from this schema should track state and config versions
func (schema *Schema) StateVersioning() bool {
	statefulRaw, ok := schema.Metadata["state_versioning"]
	if !ok {
		return false
	}
	stateful, ok := statefulRaw.(bool)
	if !ok {
		return false
	}
	return stateful
}

func (schema *Schema) SyncKeyTemplate() string {
	syncKeyTemplateRaw, ok := schema.Metadata["sync_key_template"]
	if !ok {
		return ""
	}
	syncKeyTemplate, ok := syncKeyTemplateRaw.(string)
	if !ok {
		return ""
	}
	return syncKeyTemplate
}

func (schema *Schema) GenerateCustomPath(data map[string]interface{}) (string, error) {
	path := ""
	var syncKeyTemplatePathSplit []string = strings.Split(schema.SyncKeyTemplate(), "/")
	for _, partOfPath := range syncKeyTemplatePathSplit {
		substitution := ""
		if strings.HasPrefix(partOfPath, ":") {
			prop := strings.TrimPrefix(partOfPath, ":")
			if data[prop] != nil {
				substitution = data[prop].(string)
			} else {
				return "", fmt.Errorf("Error in generating custom path %s: there is no such property %s",
					schema.SyncKeyTemplate(), prop)
			}

		} else {
			substitution = partOfPath
		}
		if path != "" {
			path = path + "/" + substitution
		} else {
			path = substitution
		}
	}
	return "/" + path, nil
}

func GetSchemaByPath(path string) *Schema {
	var schemaByPath *Schema
	for _, schema := range GetManager().Schemas() {
		if strings.HasPrefix(path, schema.URL) {
			schemaByPath = schema
			break
		}
	}
	return schemaByPath
}

// FormatParentID ...
func FormatParentID(parent string) string {
	return fmt.Sprintf("%s_id", parent)
}

func (schema *Schema) relatedSchemas() []string {
	schemas := []string{}
	for _, p := range schema.Properties {
		if p.Relation != "" {
			schemas = append(schemas, p.Relation)
		}
	}
	schemas = util.ExtendStringList(schemas, schema.Extends)
	return schemas
}

// Extend extends target schema
func (schema *Schema) Extend(fromSchema *Schema) error {
	if schema.Parent == "" {
		schema.Parent = fromSchema.Parent
	}
	if schema.Prefix == "" {
		schema.Prefix = fromSchema.Prefix
	}
	if schema.URL == "" {
		schema.URL = fromSchema.URL
	}
	if schema.NamespaceID == "" {
		schema.NamespaceID = fromSchema.NamespaceID
	}
	schema.JSONSchema["properties"] = util.ExtendMap(
		util.MaybeMap(schema.JSONSchema["properties"]),
		util.MaybeMap(fromSchema.JSONSchema["properties"]))

	schema.JSONSchema["propertiesOrder"] = util.ExtendStringList(
		util.MaybeStringList(fromSchema.JSONSchema["propertiesOrder"]),
		util.MaybeStringList(schema.JSONSchema["propertiesOrder"]))

MergeAction:
	for _, action := range fromSchema.Actions {
		for _, existingAction := range schema.Actions {
			if action.ID == existingAction.ID {
				continue MergeAction
			}
		}
		schema.Actions = append(schema.Actions, action)
	}
	schema.Metadata = util.ExtendMap(schema.Metadata, fromSchema.Metadata)
	return schema.Init()
}

//JSON returns json format of schema
func (schema *Schema) JSON() map[string]interface{} {
	return map[string]interface{}{
		"id":          schema.ID,
		"plural":      schema.Plural,
		"title":       schema.Title,
		"description": schema.Description,
		"parent":      schema.Parent,
		"singular":    schema.Singular,
		"prefix":      schema.Prefix,
		"url":         schema.URL,
		"namespace":   schema.NamespaceID,
		"schema":      schema.JSONSchema,
		"metadata":    schema.Metadata,
	}
}
