package provider

import (
	"fmt"
	"time"

	"github.com/kubernetes-incubator/external-dns/endpoint"
	"github.com/kubernetes-incubator/external-dns/plan"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// RFC2136ProviderConfig Provides the configuration
type RFC2136ProviderConfig struct {
	Nameserver  string
	ZoneName    string
	TsigKeyName string
	TsigSecret  string
	Insecure    bool
}

// RFC2136Provider Provides the configuration
type RFC2136Provider struct {
	Config RFC2136ProviderConfig
}

// ApplyChanges takes a list of changes (endpoints) and updates the remote server
func (r RFC2136Provider) ApplyChanges(changes *plan.Changes) error {

	startTime := time.Now()

	// Create
	for _, change := range changes.Create {
		log.Debugf("CREATE: %+v", change)
	}
	// We only attempt to mutate records if there are any to mutate.  A
	// call to mutate records with an empty list of endpoints is still a
	// valid call and a no-op, but we might as well not make the call to
	// prevent unnecessary logging
	if len(changes.Create) > 0 {
		// "Replacing" non-existant records creates them
		for _, ep := range changes.Create {
			r.AddRecord(*ep)
		}
	}

	// Update
	for _, change := range changes.UpdateOld {
		// Since PDNS "Patches", we don't need to specify the "old"
		// record. The Update New change type will automatically take
		// care of replacing the old RRSet with the new one We simply
		// leave this logging here for information
		log.Debugf("UPDATE-OLD (ignored): %+v", change)
	}

	for _, change := range changes.UpdateNew {
		log.Debugf("UPDATE-NEW: %+v", change)
	}
	if len(changes.UpdateNew) > 0 {
		for _, ep := range changes.UpdateNew {
			r.UpdateRecord(*ep)
		}
	}

	// Delete
	for _, change := range changes.Delete {
		log.Debugf("DELETE: %+v", change)
	}
	if len(changes.Delete) > 0 {
		for _, ep := range changes.Delete {
			r.RemoveRecord(*ep)
		}
	}

	log.Debugf("Changes pushed out to DNS in %s\n", time.Since(startTime))
	log.Debugf("Changes pushed out to DNS: %s\n", r.Config.Nameserver)

	return nil
}

// Records returns all DNS records controlled by the configured DNS server for the specified zone
func (r RFC2136Provider) Records() ([]*endpoint.Endpoint, error) {
	// log.SetLevel(log.DebugLevel)
	log.Debugf("Fetching records for '%s'", r.Config.ZoneName)
	t := new(dns.Transfer)
	if !r.Config.Insecure {
		t.TsigSecret = map[string]string{r.Config.TsigKeyName: r.Config.TsigSecret}
	}

	m := new(dns.Msg)
	m.SetAxfr(r.Config.ZoneName)
	if !r.Config.Insecure {
		m.SetTsig(r.Config.TsigKeyName, dns.HmacMD5, 300, time.Now().Unix())
	}

	env, err := t.In(m, r.Config.Nameserver)
	if err != nil {
		return nil, fmt.Errorf("Failed to fetch records via AXFR: %v", err)
	}

	records := make([]dns.RR, 0)
	for e := range env {
		if e.Error != nil {
			if e.Error == dns.ErrSoa {
				log.Error("AXFR error: unexpected response received from the server")
			} else {
				log.Errorf("AXFR error: %v", e.Error)
			}
			continue
		}
		records = append(records, e.RR...)
	}

	var result []*endpoint.Endpoint

	for _, rr := range records {
		var rrType = "A"
		var rrValues []string

		switch rr.Header().Rrtype {
		case dns.TypeCNAME:
			rrValues = []string{rr.(*dns.CNAME).Target}
			rrType = "CNAME"
		case dns.TypeA:
			rrValues = []string{rr.(*dns.A).A.String()}
			rrType = "A"
		case dns.TypeAAAA:
			rrValues = []string{rr.(*dns.AAAA).AAAA.String()}
			rrType = "AAAA"
		case dns.TypeTXT:
			rrValues = rr.(*dns.TXT).Txt
			rrType = "TXT"
		default:
			continue // Unhandled record type
		}

		e := endpoint.NewEndpointWithTTL(rr.Header().Name, rrType, endpoint.TTL(rr.Header().Ttl), rrValues...)
		result = append(result, e)
	}
	return result, nil
}

// NewRFC2136Provider initializes a new Dyn Provider.
func NewRFC2136Provider(config RFC2136ProviderConfig) (RFC2136Provider, error) {
	return RFC2136Provider{
		Config: config,
	}, nil
}

// AddRecord takes an endpoint and performs the actual DNS update
func (r *RFC2136Provider) AddRecord(record endpoint.Endpoint) error {
	log.SetLevel(log.DebugLevel)
	log.Debugf("Adding RRset '%s %s'", record.DNSName, record.RecordType)
	m := new(dns.Msg)
	m.SetUpdate(r.Config.ZoneName)
	rrs := make([]dns.RR, 0)
	log.Infof("Adding RR: '%s %d %s %s'", record.DNSName, record.RecordTTL, record.RecordType, record.Targets)
	rr, err := dns.NewRR(fmt.Sprintf("%s %d %s %s", record.DNSName, record.RecordTTL, record.RecordType, record.Targets))
	if err != nil {
		return fmt.Errorf("Failed to build RR: %v", err)
	}
	rrs = append(rrs, rr)

	m.Insert(rrs)
	err = r.sendMessage(m)
	if err != nil {
		return fmt.Errorf("RFC2136 query failed: %v", err)
	}

	return nil
}

//RemoveRecord removes tha ctual entry from DNS
func (r *RFC2136Provider) RemoveRecord(record endpoint.Endpoint) error {
	log.Infof("Removing RRset '%s %s'", record.DNSName, record.RecordType)
	m := new(dns.Msg)
	m.SetUpdate(r.Config.ZoneName)
	rr, err := dns.NewRR(fmt.Sprintf("%s 0 %s 0.0.0.0", record.DNSName, record.RecordType))
	if err != nil {
		return fmt.Errorf("Could not construct RR: %v", err)
	}

	rrs := make([]dns.RR, 1)
	rrs[0] = rr
	m.RemoveRRset(rrs)
	err = r.sendMessage(m)
	if err != nil {
		return fmt.Errorf("RFC2136 query failed: %v", err)
	}

	return nil
}

//UpdateRecord is a convinence wrapper
func (r *RFC2136Provider) UpdateRecord(record endpoint.Endpoint) error {
	err := r.RemoveRecord(record)
	if err != nil {
		return err
	}

	return r.AddRecord(record)
}

func (r *RFC2136Provider) sendMessage(msg *dns.Msg) error {
	c := new(dns.Client)
	c.SingleInflight = true

	if !r.Config.Insecure {
		c.TsigSecret = map[string]string{r.Config.TsigKeyName: r.Config.TsigSecret}
		msg.SetTsig(r.Config.TsigKeyName, dns.HmacMD5, 300, time.Now().Unix())
	}

	resp, _, err := c.Exchange(msg, r.Config.Nameserver)
	if err != nil {
		return err
	}

	if resp != nil && resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("Bad return code: %s", dns.RcodeToString[resp.Rcode])
	}

	return nil
}
