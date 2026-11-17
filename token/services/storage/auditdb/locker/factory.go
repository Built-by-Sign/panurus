/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package locker

import (
	"database/sql"

	"github.com/LFDT-Panurus/panurus/token/services/storage/auditdb/locker/id"
	"github.com/LFDT-Panurus/panurus/token/services/storage/auditdb/locker/memory"
	lockerpostgres "github.com/LFDT-Panurus/panurus/token/services/storage/auditdb/locker/postgres"
	dbdriver "github.com/LFDT-Panurus/panurus/token/services/storage/db/driver"
	sqlpostgres "github.com/LFDT-Panurus/panurus/token/services/storage/db/sql/postgres"
	"github.com/hyperledger-labs/fabric-smart-client/pkg/utils/errors"
)

// WriteDBProvider is an optional interface that SQL-backed AuditTransactionStore
// implementations may satisfy to expose their underlying *sql.DB.
type WriteDBProvider interface {
	WriteDB() *sql.DB
}

// The postgres audit store must keep satisfying WriteDBProvider; both ends match dynamically.
var _ WriteDBProvider = (*sqlpostgres.AuditTransactionStore)(nil)

// NewFromConfig builds a Locker with the default schema creation policy.
func NewFromConfig(cfg Config, store any, replicaID id.ReplicaIDProvider) (Locker, error) {
	return NewFromConfigWithSchemaPolicy(cfg, store, replicaID, nil)
}

// NewFromConfigWithSchemaPolicy resolves the persistence's schema creation policy only for backends that use it.
// A nil resolver keeps the backend's default behavior.
func NewFromConfigWithSchemaPolicy(
	cfg Config, store any, replicaID id.ReplicaIDProvider, shouldSkipCreateTable func() (bool, error),
) (Locker, error) {
	switch cfg.Backend {
	case BackendPostgres:
		dbp, ok := store.(WriteDBProvider)
		if !ok {
			return nil, errors.New("postgres locker backend requires a SQL-backed audit store (WriteDBProvider)")
		}
		ats, ok := store.(dbdriver.AuditTransactionStore)
		if !ok {
			return nil, errors.New("postgres locker backend requires an AuditTransactionStore")
		}

		var opts []lockerpostgres.Option
		if shouldSkipCreateTable != nil {
			skip, err := shouldSkipCreateTable()
			if err != nil {
				return nil, errors.Wrap(err, "failed to resolve locker schema creation policy")
			}
			if skip {
				opts = append(opts, lockerpostgres.WithPrecreatedSchema())
			}
		}

		return lockerpostgres.New(
			dbp.WriteDB(),
			ats.PrefixedTableName("eid_leases"),
			cfg.Postgres,
			replicaID,
			opts...,
		)
	case BackendMemory, "":
		return memory.NewWithConfig(cfg.Memory), nil
	default:
		return nil, errors.Errorf("unknown locker backend: %s", cfg.Backend)
	}
}
