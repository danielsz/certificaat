(ns certificaat.acme4j.registration
  (:require [certificaat.acme4j.account :as account]
            [certificaat.acme4j.session :as session]
            [certificaat.util.tentoonstelling :as t]
            [certificaat.domain :refer [Certificaat]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]])
  (:import [org.shredzone.acme4j Registration RegistrationBuilder]
           [org.shredzone.acme4j.exception AcmeException AcmeConflictException]))

(defn accept-agreement [reg]
  (let [url (.getAgreement reg)]
    (t/show-tos "Terms of Service:" "The agreement has been saved to disk. By clicking OK you are accepting the terms.")
    (.commit (.setAgreement (.modify reg) url))
    (log/info "Agreement accepted")
    reg))

(defn create [keypair acme-uri contact]
  (let [session (session/create keypair acme-uri)]
    (try
      (let [builder (-> (RegistrationBuilder.)
                        (.addContact contact))
            reg (.create builder session)]
        (log/info "Registered a new user, URI:" (.getLocation reg))
        reg)
      (catch AcmeConflictException e
        (let [reg (Registration/bind session (.getLocation e))]
          (log/warn "Account already exists, URI:" (.getLocation reg))
          reg))
      (catch AcmeException e (log/error (.getMessage e))))))

(defn swap-keys [reg new-keypair]
  (.changeKey reg new-keypair))

(defn restore [session uri]
  (Registration/bind session uri))

(defn delete [reg]
  (.deactivate reg))

(extend-type Registration
  Certificaat
  (valid? [this] true))
