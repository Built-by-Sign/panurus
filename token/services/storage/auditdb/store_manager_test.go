/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package auditdb_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/LFDT-Panurus/panurus/token"
	"github.com/LFDT-Panurus/panurus/token/sdk/tms"
	tokenconfig "github.com/LFDT-Panurus/panurus/token/services/config"
	"github.com/LFDT-Panurus/panurus/token/services/storage/auditdb"
	"github.com/LFDT-Panurus/panurus/token/services/storage/db/multiplexed"
	"github.com/LFDT-Panurus/panurus/token/services/storage/db/sql/postgres"
	fscconfig "github.com/hyperledger-labs/fabric-smart-client/platform/view/services/config"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/storage/driver/common"
	fscpostgres "github.com/hyperledger-labs/fabric-smart-client/platform/view/services/storage/driver/sql/postgres"
	"github.com/stretchr/testify/require"
)

type fixedDBProvider struct{ db *sql.DB }

func (p fixedDBProvider) Get(fscpostgres.Opts) (*common.RWDB, error) {
	return &common.RWDB{ReadDB: p.db, WriteDB: p.db}, nil
}

func TestStoreManager_LockerUsesAuditPersistenceSchemaPolicy(t *testing.T) {
	const configYAML = `
fsc:
  persistences:
    default:
      type: postgres
      opts:
        dataSource: default-dsn
        skipCreateTable: false
    audit:
      type: postgres
      opts:
        dataSource: audit-dsn
        skipCreateTable: true
token:
  tms:
    test:
      network: net
      channel: channel
      namespace: tok
      auditdb:
        persistence: audit
      auditor:
        locker:
          backend: postgres
          postgres:
            owner: auditor-test
`
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "core.yaml"), []byte(configYAML), 0o600))
	cp, err := fscconfig.NewProvider(dir)
	require.NoError(t, err)

	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	mock.ExpectQuery(`^SELECT eid, anchor, owner, expires_at FROM [a-z0-9_]+ LIMIT 0$`).
		WillReturnRows(sqlmock.NewRows([]string{"eid", "anchor", "owner", "expires_at"})).RowsWillBeClosed()

	drivers := multiplexed.NewDriver(cp, postgres.NewNamedDriver(cp, fixedDBProvider{db: db}, nil))
	manager := auditdb.NewStoreServiceManager(tms.NewConfigServiceWrapper(tokenconfig.NewService(cp)), drivers, nil)
	_, err = manager.StoreServiceByTMSId(token.TMSID{Network: "net", Channel: "channel", Namespace: "tok"})
	require.NoError(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}
