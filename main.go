package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Kaese72/asset-registry/apierrors"
	"github.com/Kaese72/asset-registry/internal/application"
	"github.com/Kaese72/asset-registry/internal/database"

	registryModels "github.com/Kaese72/asset-registry/registry/models"
	findingRegistryModels "github.com/Kaese72/finding-registry/event"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"

	amqp "github.com/rabbitmq/amqp091-go"
)

type webApplication struct {
	application application.Application
	jwtSecret   string
}

func terminalHTTPError(w http.ResponseWriter, err error) {
	var apiError apierrors.APIError
	if errors.As(err, &apiError) {
		if apiError.Code == 500 {
			// When an unknown error occurs, do not send the error to the client
			http.Error(w, "Internal Server Error", apiError.Code)
			log.Print(err.Error())
			return

		} else {
			bytes, intErr := json.MarshalIndent(apiError, "", "   ")
			if intErr != nil {
				// Must send a normal Error an not APIError just in case of eternal loop
				terminalHTTPError(w, fmt.Errorf("error encoding response: %s", intErr.Error()))
				return
			}
			http.Error(w, string(bytes), apiError.Code)
			return
		}
	} else {
		terminalHTTPError(w, apierrors.APIError{Code: http.StatusInternalServerError, WrappedError: err})
		return
	}
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
	assets, err := app.application.ReadAssets(r.Context(), parseQueryFilters(r))
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(assets); err != nil {
		terminalHTTPError(w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) readAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(organizationIDKey).(float64))
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	asset, err := app.application.ReadAsset(r.Context(), id, organizationId)
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(asset); err != nil {
		terminalHTTPError(w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) createAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := r.Context().Value(organizationIDKey).(float64)
	inputAsset := registryModels.Asset{}
	if err := json.NewDecoder(r.Body).Decode(&inputAsset); err != nil {
		terminalHTTPError(w, fmt.Errorf("error decoding request: %s", err.Error()))
		return
	}
	asset, err := app.application.CreateAsset(r.Context(), inputAsset, int(organizationId))
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(asset); err != nil {
		terminalHTTPError(w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) updateAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(organizationIDKey).(float64))
	inputAsset := registryModels.Asset{}
	if err := json.NewDecoder(r.Body).Decode(&inputAsset); err != nil {
		terminalHTTPError(w, fmt.Errorf("error decoding request: %s", err.Error()))
		return
	}

	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	asset, err := app.application.UpdateAsset(r.Context(), inputAsset, id, organizationId)
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(asset); err != nil {
		terminalHTTPError(w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) deleteAsset(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(organizationIDKey).(float64))
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	err := app.application.DeleteAsset(r.Context(), id, organizationId)
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}
}

func (app webApplication) readReportScopes(w http.ResponseWriter, r *http.Request) {
	scopes, err := app.application.ReadReportScopes(r.Context(), parseQueryFilters(r))
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}

	// Write JSON response
	w.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "   ")
	if err := encoder.Encode(scopes); err != nil {
		terminalHTTPError(w, fmt.Errorf("error encoding response: %s", err.Error()))
		return
	}
}

func (app webApplication) deleteReportScope(w http.ResponseWriter, r *http.Request) {
	organizationId := int(r.Context().Value(organizationIDKey).(float64))
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"]) // Ignoring error because mux guarantees this is an int
	err := app.application.DeleteReportScope(r.Context(), id, organizationId)
	if err != nil {
		terminalHTTPError(w, fmt.Errorf("error from database: %s", err.Error()))
		return
	}
}

type contextKey string

const (
	userIDKey         contextKey = "userID"
	organizationIDKey contextKey = "organizationID"
)

func (app webApplication) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return []byte(app.jwtSecret), nil
		})

		if err != nil {
			terminalHTTPError(w, apierrors.APIError{Code: http.StatusUnauthorized, WrappedError: fmt.Errorf("error parsing token: %s", err.Error())})
			return
		}

		if !token.Valid {
			terminalHTTPError(w, apierrors.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("invalid token")})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			terminalHTTPError(w, apierrors.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("could not read claims")})
			return
		}

		userID, ok := claims[string(userIDKey)].(float64)
		if !ok {
			terminalHTTPError(w, apierrors.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("could not read userId claim")})
			return
		}
		organizationID, ok := claims[string(organizationIDKey)].(float64)
		if !ok {
			terminalHTTPError(w, apierrors.APIError{Code: http.StatusUnauthorized, WrappedError: errors.New("could not read organizationId claim")})
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		ctx = context.WithValue(ctx, organizationIDKey, organizationID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
		true,       // auto-ack
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
					log.Printf("error parsing message: %s", err.Error())
					continue
				}
				_, err = app.PutReportScope(registryModels.ReportScope{
					Type:  findingUpdate.ReportLocator.Type,
					Value: findingUpdate.ReportLocator.Value,
				},
					findingUpdate.OrganizationId,
				)
				if err != nil {
					log.Printf("Error while PUTting discovered scope: %s", err.Error())
					continue
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
		log.Fatal(err.Error())
	}

	if Loaded.Database.Host == "" {
		log.Fatal("Database host not set")
	}

	if Loaded.Database.Password == "" {
		log.Fatal("Database password not set")
	}

	if Loaded.Database.User == "" {
		log.Fatal("Database user not set")
	}

	if Loaded.JWT.Secret == "" {
		log.Fatal("JWT secret key not set")
	}

	if Loaded.Event.ConnectionString == "" {
		log.Fatal("Event connection string not set")
	}
}

func main() {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", Loaded.Database.User, Loaded.Database.Password, Loaded.Database.Host, Loaded.Database.Port, Loaded.Database.Database))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	application := application.NewApplication(db)

	webapp := webApplication{
		application: application,
		jwtSecret:   Loaded.JWT.Secret,
	}

	router := mux.NewRouter()
	router.Use(webapp.authMiddleware)

	// Assets
	router.HandleFunc("/assets", webapp.readAssets).Methods("GET")
	router.HandleFunc("/assets", webapp.createAsset).Methods("POST")
	router.HandleFunc("/assets/{id:[0-9]+}", webapp.updateAsset).Methods("POST")
	router.HandleFunc("/assets/{id:[0-9]+}", webapp.readAsset).Methods("GET")
	router.HandleFunc("/assets/{id:[0-9]+}", webapp.deleteAsset).Methods("DELETE")

	// Report scopes
	router.HandleFunc("/assets/reportScopes", webapp.readReportScopes).Methods("GET")
	router.HandleFunc("/assets/reportScopes/{id:[0-9]+}", webapp.deleteReportScope).Methods("DELETE")

	startFindingUpdateListener(context.Background(), application, Loaded.Event.ConnectionString, Loaded.Event.FindingUpdates)

	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", Loaded.Listen.Host, Loaded.Listen.Port), router))
}
