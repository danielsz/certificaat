(ns certificaat.kung-fu
  (:require
   [certificaat.acme4j.session :as session]
   [certificaat.acme4j.keypair :as keypair]
   [certificaat.acme4j.account :as account]
   [certificaat.acme4j.challenge :as challenge]
   [certificaat.acme4j.order :as order]
   [certificaat.acme4j.authorization :as authorization]
   [certificaat.acme4j.certificate :as certificate]
   [certificaat.utils :refer [exit load-url]]
   [certificaat.domain :as d]
   [clj-http.client :as client]
   [clojure.java.io :as io]
   [clojure.string :as str]
   [clojure.tools.logging :as log]
   [clojure.spec.alpha :as s]
   [clj-http.client :as client])
  (:import java.net.URI
           org.shredzone.acme4j.exception.AcmeUnauthorizedException
           org.shredzone.acme4j.Status))

(defn valid? [path {:keys [config-dir keypair-filename acme-uri] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)]
    (condp s/valid? (.getName (io/as-file path))
      ::d/account-url (when (.exists (io/file path))
                        (let [account (account/restore session keypair)]
                          (d/valid? account)))
      ::d/order-url (when (.exists (io/file path))
                      (let [order (order/restore login path)]
                        (d/valid? order)))
      ::d/authorization-url (when (.exists (io/file path))
                              (let [authorization (authorization/restore login path)]
                                (d/valid? authorization)))
      ::d/certificate-url (when (.exists (io/file path))
                           (let [certificate (certificate/restore login path)]
                             (d/valid? certificate))))))

(defn invalid? [path {:keys [config-dir keypair-filename acme-uri] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)]
    (condp s/valid? (.getName (io/as-file path))
      ::d/account-url (when (.exists (io/file path))
                        (let [account (account/restore session keypair)]
                          (d/invalid? account)))
      ::d/order-url (when (.exists (io/file path))
                      (let [order (order/restore login path)]
                        (d/invalid? order)))
      ::d/authorization-url (when (.exists (io/file path))
                              (let [authorization (authorization/restore login path)]
                                (d/invalid? authorization)))
      ::d/certificate-url (when (.exists (io/file path))
                           (let [certificate (certificate/restore login path)]
                             (d/invalid? certificate))))))

(defn pending? [path {:keys [config-dir keypair-filename acme-uri] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)]
    (condp s/valid? (.getName (io/as-file path))
      ::d/order-url (when (.exists (io/file path))
                      (let [order (order/restore login path)]
                        (d/pending? order)))
      ::d/authorization-url (when (.exists (io/file path))
                              (let [authorization (authorization/restore login path)]
                                (d/pending? authorization)))
      ::d/certificate-url (when (.exists (io/file path))
                            (let [certificate (certificate/restore login path)]
                             (d/pending? certificate))))))

(defn account [{:keys [config-dir keypair-filename acme-uri contact] :as options}]
  (if-let [account-url (load-url (str config-dir "account.url"))]
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)]
      (account/read session keypair))
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)
          account (account/create session keypair contact :with-login false)]
      (d/marshal account (str config-dir "account.url"))
      account)))


(defn order [{:keys [config-dir keypair-filename acme-uri domain san] :as options}]
  (if-let [order-url (load-url (str config-dir domain "/order.url"))]
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)
          login (account/login (str config-dir "account.url") keypair session)]
      (order/restore login (str config-dir domain "/order.url")))
    (let [session (session/create acme-uri)
          keypair (keypair/read config-dir keypair-filename)
          account (account/restore session keypair)
          domains (if san (conj san domain) [domain])
          order-builder (doto (.newOrder account)
                          (.domains domains))
          order (order/create account domains)]
      (d/marshal order (str config-dir domain "/order.url"))
      order)))

(defn authorize [{:keys [config-dir keypair-filename acme-uri domain] :as options}]
  (let  [session (session/create acme-uri)
         keypair (keypair/read config-dir  keypair-filename)
         login (account/login (str (:config-dir options) "/account.url") keypair session)
         order (order/restore login (str (:config-dir options) (:domain options) "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :when (not (.isWildcard auth))]
      (d/marshal auth (str (:config-dir options) (:domain options) "/authorization." (.getDomain (.getIdentifier auth)) ".url")))))

(defn challenge [{domain :domain config-dir :config-dir acme-uri :acme-uri :as options}]
  (let  [session (session/create acme-uri)
         keypair (keypair/read (:config-dir options) (:keypair-filename options))
         login (account/login (str config-dir "account.url") keypair session)
         order (order/restore login (str config-dir domain "/order.url"))]
    (doseq [auth (.getAuthorizations order)
            :let [challenge (challenge/find auth (first (:challenges options)))
                  domain (.getDomain (.getIdentifier auth))]]
      (d/marshal challenge (str config-dir (:domain options) "/challenge." domain ".url"))
      (println (challenge/explain challenge (.getDomain (.getIdentifier auth)))))))


(defn get-challenges [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        order (order/restore login (str config-dir domain "/order.url"))]
    (for [auth (.getAuthorizations order)
          :let [challenge (challenge/find auth (first (:challenges options)))]]
      challenge)))

(defn accept-challenges [{:keys [domain config-dir acme-uri keypair-filename] :as options}]
  (let [session (session/create acme-uri)
        keypair (keypair/read config-dir keypair-filename)
        login (account/login (str config-dir "account.url") keypair session)
        order (order/restore login (str config-dir domain "/order.url"))]     
    (doseq [auth (.getAuthorizations order)
            :let [challenge (challenge/find auth (first (:challenges options)))]]
      (challenge/accept challenge))))

(defn get-certificate [{:keys [config-dir domain organisation san] :as options} reg]
  (let [path (str config-dir domain "/")
        csr (str path "request.csr")]
    (if (.exists (io/file csr))
      (let [csrb (certificate/load-certificate-request csr)]
        ;(certificate/request csrb reg)
        )
      (let [domain-keypair (account/restore path "domain.key")
            csrb (certificate/prepare domain-keypair domain organisation (when san san))]
        (certificate/persist-certificate-request csr csrb)
        ;(certificate/request csrb reg)
        ))))

(defn request-certificate [{config-dir :config-dir domain :domain :as options} reg]
  (let [path (str config-dir domain "/")
        cert (get-certificate options reg)]
    (certificate/persist (str path "domain-chain.crt") cert)
    (spit (str path "certificate.url") (.getLocation cert))
    (log/info "Well done! You will find your certificate chain in" path)))

(def explain challenge/explain)
