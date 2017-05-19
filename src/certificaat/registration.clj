(ns certificaat.registration
  (:require [certificaat.account :as account]
            [certificaat.session :as session]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]])
  (:import [org.shredzone.acme4j Registration RegistrationBuilder]
           [org.shredzone.acme4j.exception AcmeException AcmeConflictException]))

(defn accept-agreement [reg]
  (let [agreement (.getAgreement reg)]
    (log/info "Terms of Service:" agreement)
    (.commit (.setAgreement (.modify reg) agreement))
    (log/info "Agreement accepted")
    reg))

(defn create
  ([] (let [keypair (account/load-from-disk)]
        (create keypair)))
  ([keypair] (let [session (session/create keypair)]
               (try
                 (let [builder (-> (RegistrationBuilder.)
                                   (.addContact (:acme-contact env)))            
                       reg (.create builder session)]
                   (log/info "Registered a new user, URI:" (.getLocation reg))
                   (accept-agreement reg))
                 (catch AcmeConflictException e
                   (let [reg (Registration/bind session (.getLocation e))]
                     (log/warn "Account already exists, URI:" (.getLocation reg))
                     reg))
                 (catch AcmeException e (log/error (.getMessage e)))))))

(defn swap-keys [reg new-keypair]
  (.changeKey reg new-keypair))

(defn delete [reg]
  (.deactivate reg))
