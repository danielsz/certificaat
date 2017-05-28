(ns certificaat.interface.boot
  (:require [certificaat.kung-fu :as k]
            [certificaat.domain :as d]
            [boot.core :as boot :refer [deftask with-pre-wrap]]
            [boot.util :as util]
            [clojure.java.io :as io]
            [clojure.string :as str]
            [clojure.core.async :refer [<!!]])
  (:import java.net.URI
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeServerException]))

(deftask certificaat-setup
  "Certificaat setup. Will create the configuration directory and create the account keys."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file used to register the ACME account."
   m domain DOMAIN str "The domain you wish to authorize"
   t key-type KEY-TYPE kw "The key type, one of RSA or Elliptic Curve."
   s key-size KEY-SIZE int "Key length used to create a RSA private key."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "account.key"
                  :key-type :rsa
                  :key-size 2048}
        options (try
                (d/validate ::d/certificaat-setup (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type options)
        Throwable (let [e options]
                    (if (= "Invalid options" (.getMessage e))
                      (util/warn (ex-data e))
                      (*usage*))
                    e)
        (k/setup options))
      fileset)))

(deftask certificaat-authorize
  "Certificaat authorize a domain with ACME server. Will find a challenge and save the challenge URI."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   m domain DOMAIN str "The domain you wish to authorize"
   a contact CONTACT str "The email address used to send you expiry notices (mailto:me@example.com)"
   c challenges CHALLENGES #{str} "The challenges you can complete"
   s san SAN #{str} "Subject Alternative Name (SAN). Additional domains to be authorized."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "account.key"
                  :acme-uri "acme://letsencrypt.org/staging"
                  :challenges #{"http-01"}}
        options (try
                (d/validate ::d/certificaat-authorize (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type options)
        Throwable (let [e options]
                    (if (= "Invalid options" (.getMessage e))
                      (util/warn "%s\n" (ex-data e))
                      (*usage*))
                    e)
        (let [{config-dir :config-dir domain :domain} options
              reg (k/register options)]
          (doseq [[name challenges] (k/authorize options reg)
                  i (range (count challenges))
                  challenge challenges
                  :let [explanation (k/explain challenge name)]]
            (util/info "%s\n" explanation)
            (spit (str config-dir domain "/" name "." (.getType challenge) ".challenge.txt") explanation)
            (spit (str config-dir domain "/challenge." name "." i ".uri") (.getLocation challenge)))))
      fileset)))

(deftask certificaat-challenge
  "Certificaat will attempt to complete all challenges."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   m domain DOMAIN str "The domain you wish to authorize"
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "account.key"
                  :acme-uri "acme://letsencrypt.org/staging"}
        options (try
                (d/validate ::d/certificaat-challenge (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type options)
        Throwable (let [e options]
                    (if (= "Invalid options" (.getMessage e))
                      (util/warn (ex-data e))
                      (*usage*))
                    e)
        (doseq [c (k/challenge options)
                :let [resp (<!! c)]]
          (if (= Status/VALID resp)
            (util/info "Well done, challenge completed.")
            (util/warn "Sorry, challenge failed. %s\n" resp))))
      fileset)))

(deftask certificaat-request
  "Certificaat will request the certificate and save in the configuration directory."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."
   m domain DOMAIN str "The domain you wish to authorize"
   a contact CONTACT str "The email address used to send you expiry notices (mailto:me@example.com)"
   o organisation ORGANISATION str "The organisation you with to register with the cerfiticate"
   s san SAN #{str} "Subject Alternative Name (SAN). Additional domains to be authorized."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "account.key"
                  :acme-uri "acme://letsencrypt.org/staging"}
        options (try
                (d/validate ::d/certificaat-request (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type options)
        Throwable (let [e options]
                    (if (= "Invalid options" (.getMessage e))
                      (util/warn "%s\n" (ex-data e))
                      (*usage*))
                    e)
        (let [reg (k/register options)]
          (k/request options reg)))
      fileset)))

(deftask certificaat-renew
  "Certificaat will attempt to complete all challenges."
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   k keypair-filename KEYPAIR-FILENAME str "The name of the keypair file for your account."
   m domain DOMAIN str "The domain you wish to authorize"
   u acme-uri ACME-URI str "The URI of the ACME server’s directory service as documented by the CA."]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")
                  :keypair-filename "account.key"
                  :acme-uri "acme://letsencrypt.org/staging"}
        options (try
                (d/validate ::d/certificaat-renew (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type options)
        Throwable (let [e options]
                    (if (= "Invalid options" (.getMessage e))
                      (util/warn (ex-data e))
                      (*usage*))
                    e)
        (k/renew options))
      fileset)))

(deftask certificaat-info
  [d config-dir CONFIG-DIR str "The configuration directory for certificaat. Follows XDG folders convention."
   m domain DOMAIN str "The domain you wish to authorize"]
  (let [defaults {:config-dir (str (System/getProperty "user.home") "/.config/certificaat/")}
        options (try
                (d/validate ::d/certificaat-info (merge defaults *opts*))
                (catch Exception e e))]
    (with-pre-wrap fileset
      (condp #(isa? %2 %1) (type options)
        Throwable (let [e options]
                    (if (= "Invalid options" (.getMessage e))
                      (util/warn "%s\n" (ex-data e))
                      (*usage*))
                    e)
        (util/info "%s\n" (k/info options)))
      fileset)))

(deftask authorize []
  (comp
   (certificaat-setup :domain "teamsocial.me")
   (certificaat-authorize :domain "teamsocial.me" :challenges #{"dns-01"} :san #{"www.teamsocial.me"} :contact "mailto:daniel.szmulewicz@gmail.com")))

(deftask request []
  (comp
   (certificaat-challenge :domain "teamsocial.me")
   (certificaat-request :domain "teamsocial.me" :organisation "Sapiens Sapiens" :san #{"www.teamsocial.me"} :contact "mailto:daniel.szmulewicz@gmail.com")
   (certificaat-info :domain "teamsocial.me")))

(deftask renew []
  (comp (certificaat-renew :domain "teamsocial.me")
        (certificaat-info :domain "teamsocial.me")))

