package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"go.elastic.co/apm/module/apmsql"
	_ "go.elastic.co/apm/module/apmsql/mysql"

	"github.com/Kaese72/riskie-lib/apierror"
	"github.com/Kaese72/riskie-lib/logging"
	"go.elastic.co/apm/module/apmgorilla"

	"github.com/Kaese72/asset-registry/internal/application"
	"github.com/Kaese72/asset-registry/internal/database"

	registryModels "github.com/Kaese72/asset-registry/registry/models"
	findingRegistryModels "github.com/Kaese72/finding-registry/event"
	"github.com/Kaese72/organization-registry/authentication"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	amqp "github.com/rabbitmq/amqp091-go"
)

type webApplication struct {
	application application.Application
	jwtSecret   string
}

var queryRegex = regexp.MustCompile(`^(?P<key>\w+)\[(?P<operator>\w+)\]$`)

func parseQueryFilters(r *http.Request) []database.Filter {
	filters := []database.Filter{}
	for key, values := range r.URL.Query() {
		matches := queryRegex.FindStringSubmatch(key)
		if len(matches) == 0 {
			continue
		}
		for _, value := range values {
			filters = append(filters, database.Filter{Key: matches[queryRegex.SubexpIndex("key")], Value: value, Operator: matches[queryRegex.SubexpIndex("operator")]})
		}
	}
	return filters
}

func (app webApplication) readAssets(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(authentication.OrganizationIDKey).(float64))
	assets, err := app.application.ReadAssets(r.Context(), parseQueryFilters(r), organizationId)
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(assets); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) readAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(authentication.OrganizationIDKey).(float64))
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	asset, err := app.application.ReadAsset(r.Context(), id, organizationId)
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(asset); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) createAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := r.Context().Value(authentication.OrganizationIDKey).(float64)
	inputAsset := registryModels.Asset{}
	if err := json.NewDecoder(r.Body).Decode(&inputAsset); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error decoding request: %s", err.Error()))
		return
	}
	asset, err := app.application.CreateAsset(r.Context(), inputAsset, int(organizationId))
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(asset); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) updateAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(authentication.OrganizationIDKey).(float64))
	inputAsset := registryModels.Asset{}
	if err := json.NewDecoder(r.Body).Decode(&inputAsset); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error decoding request: %s", err.Error()))
		return
	}

	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	asset, err := app.application.UpdateAsset(r.Context(), inputAsset, id, organizationId)
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(asset); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) deleteAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(authentication.OrganizationIDKey).(float64))
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	err := app.application.DeleteAsset(r.Context(), id, organizationId)
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}
}

func (app webApplication) readReportScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := app.application.ReadReportScopes(r.Context(), parseQueryFilters(r))
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(scopes); err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) deleteReportScope(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(authentication.OrganizationIDKey).(float64))
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	err := app.application.DeleteReportScope(r.Context(), id, organizationId)
	if err != nil {
		apierror.TerminalHTTPError(r.Context(), w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}
}

func startFindingUpdateListener(ctx context.Context, app application.Application, connectionString string, queueName string) error {
	// Plagiarized from https://www.rabbitmq.com/tutorials/tutorial-one-go
	connection, err := amqp.Dial(connectionString)
	if err != nil {
		return err
	}
	// defer conn.Close()
	channel, err := connection.Channel()
	if err != nil {
		return err
	}
	queue, err := channel.QueueDeclare(
		queueName, // name
		false,     // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return err
	}
	msgs, err := channel.Consume(
		queue.Name, // queue
		"",         // consumer
		true,       // auto-ack // FIXME do not auto-ack
		false,      // exclusive
		false,      // no-local
		false,      // no-wait
		nil,        // args
	)
	if err != nil {
		return err
	}
	go func() {
		defer connection.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-msgs:
				var findingUpdate findingRegistryModels.FindingUpdate
				err := json.Unmarshal(msg.Body, &findingUpdate)
				if err != nil {
					logging.Error(context.Background(), "error parsing message", map[string]interface{}{"error": err.Error()})
					// FIXME Should not ACK the message
					continue
				}
				scope, newCreated, err := app.PutReportScope(
					ctx,
					registryModels.ReportScope{
						Type:          findingUpdate.ReportLocator.Type,
						Value:         findingUpdate.ReportLocator.Value,
						Distinguisher: findingUpdate.ReportLocator.Distinguisher,
					},
					findingUpdate.OrganizationId,
				)
				if err != nil {
					logging.Error(context.Background(), "Error while PUTting discovered scope", map[string]interface{}{"error": err.Error()})
					// FIXME Should rollback and not ACK the message
					continue
				}
				if newCreated {
					newAsset, err := app.CreateAsset(
						context.Background(),
						registryModels.Asset{
							Name:         scope.Value,
							ReportScopes: []registryModels.ReportScope{},
						},
						findingUpdate.OrganizationId,
					)
					if err != nil {
						logging.Error(context.Background(), "Error while creating asset for new scope", map[string]interface{}{"error": err.Error()})
						// FIXME Should rollback and not ACK the message
						continue
					}
					err = app.LinkReportScopeToAsset(context.Background(), newAsset.ID, scope.ID)
					if err != nil {
						logging.Error(context.Background(), "Error while linking new asset to new scope", map[string]interface{}{"error": err.Error()})
						// FIXME Should rollback and not ACK the message
						continue
					}
				}
			}
		}
	}()
	return nil
}

type Config struct {
	Database struct {
		Host     string `mapstructure:"host"`
		Port     int    `mapstructure:"port"`
		User     string `mapstructure:"user"`
		Password string `mapstructure:"password"`
		Database string `mapstructure:"database"`
	} `mapstructure:"database"`
	JWT struct {
		Secret string `mapstructure:"secret"`
	} `mapstructure:"jwt"`
	Listen struct {
		Host string `mapstructure:"host"`
		Port int    `mapstructure:"port"`
	} `mapstructure:"listen"`
	Event struct {
		FindingUpdates   string `mapstructure:"findingUpdates"`
		ConnectionString string `mapstructure:"connectionString"`
	} `mapstructure:"event"`
}

var Loaded Config

func init() {
	// Load configuration from environment
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.BindEnv("database.host")
	viper.BindEnv("database.port")
	viper.SetDefault("database.port", "3306")
	viper.BindEnv("database.user")
	viper.BindEnv("database.password")
	viper.BindEnv("database.database")
	viper.SetDefault("database.database", "assetregistry")

	// JWT configuration
	viper.BindEnv("jwt.secret")

	// HTTP listen config
	viper.BindEnv("listen.host")
	viper.SetDefault("listen.host", "0.0.0.0")
	viper.BindEnv("listen.port")
	viper.SetDefault("listen.port", "8080")

	// Event configuration
	viper.BindEnv("event.findingUpdates")
	viper.SetDefault("event.findingUpdates", "findingUpdates")
	viper.BindEnv("event.connectionString")

	err := viper.Unmarshal(&Loaded)
	if err != nil {
		logging.Fatal(context.Background(), err.Error())
	}

	if Loaded.Database.Host == "" {
		logging.Fatal(context.Background(), "Database host not set")
	}

	if Loaded.Database.Password == "" {
		logging.Fatal(context.Background(), "Database password not set")
	}

	if Loaded.Database.User == "" {
		logging.Fatal(context.Background(), "Database user not set")
	}

	if Loaded.JWT.Secret == "" {
		logging.Fatal(context.Background(), "JWT secret key not set")
	}

	if Loaded.Event.ConnectionString == "" {
		logging.Fatal(context.Background(), "Event connection string not set")
	}
}

func main() {
	db, err := apmsql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", Loaded.Database.User, Loaded.Database.Password, Loaded.Database.Host, Loaded.Database.Port, Loaded.Database.Database))
	if err != nil {
		logging.Fatal(context.Background(), err.Error())
	}
	defer db.Close()

	application := application.NewApplication(db)

	webapp := webApplication{
		application: application,
		jwtSecret:   Loaded.JWT.Secret,
	}

	router := mux.NewRouter().PathPrefix("/asset-registry").Subrouter()
	apmgorilla.Instrument(router)
	router.Use(authentication.DefaultJWTAuthentication(Loaded.JWT.Secret))

	// Assets
	router.HandleFunc("/assets", webapp.readAssets).Methods("GET")
	router.HandleFunc("/assets", webapp.createAsset).Methods("POST")
	router.HandleFunc("/assets/{id:[0-9]+}", webapp.updateAsset).Methods("PATCH")
	router.HandleFunc("/assets/{id:[0-9]+}", webapp.readAsset).Methods("GET")
	router.HandleFunc("/assets/{id:[0-9]+}", webapp.deleteAsset).Methods("DELETE")

	// Report scopes
	router.HandleFunc("/assets/reportScopes", webapp.readReportScopes).Methods("GET")
	router.HandleFunc("/assets/reportScopes/{id:[0-9]+}", webapp.deleteReportScope).Methods("DELETE")

	err = startFindingUpdateListener(context.Background(), application, Loaded.Event.ConnectionString, Loaded.Event.FindingUpdates)
	if err != nil {
		logging.Fatal(context.Background(), err.Error())
	}

	logging.Fatal(context.Background(), http.ListenAndServe(fmt.Sprintf("%s:%d", Loaded.Listen.Host, Loaded.Listen.Port), router).Error())
}
