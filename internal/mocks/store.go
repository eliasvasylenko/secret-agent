package mocks

type MockStore struct {
	Mock
}

func (s *MockStore) Activate(name string, id string, force bool) (complete func() error, err error) {
	return nextCall(&s.Mock, s.Activate)(name, id, force)
}
func (s *MockStore) Deactivate(name string, id string, force bool) (complete func() error, err error) {
	return nextCall(&s.Mock, s.Deactivate)(name, id, force)
}
func (s *MockStore) ReadActive(name string) (id *string, activating bool, deactivating bool, err error) {
	return nextCall(&s.Mock, s.ReadActive)(name)
}
func (s *MockStore) Create(id string, plan []byte, name string) (complete func() error, err error) {
	return nextCall(&s.Mock, s.Create)(id, plan, name)
}
func (s *MockStore) Destroy(id string, force bool) (complete func() error, err error) {
	return nextCall(&s.Mock, s.Destroy)(id, force)
}
func (s *MockStore) Read(id string) (plan []byte, name string, creating bool, destroying bool, err error) {
	return nextCall(&s.Mock, s.Read)(id)
}
func (s *MockStore) List(name string) (ids []string, err error) {
	return nextCall(&s.Mock, s.List)(name)
}
func (s *MockStore) ListAll() (ids []string, err error) {
	return nextCall(&s.Mock, s.ListAll)()
}
