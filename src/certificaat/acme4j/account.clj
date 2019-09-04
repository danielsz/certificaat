(ns certificaat.acme4j.account
  (:refer-clojure :exclude [read])
  (:require [environ.core :refer [env]]            
            [clojure.tools.logging :as log]
            [certificaat.acme4j.keypair :as keypair]
            [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url]])
  (:import
   [org.shredzone.acme4j Account AccountBuilder Login]))

(defn create [session keypair contact & {:keys [with-login] :or {with-login false}}]
  (let [account-builder (doto (AccountBuilder.)
                          (.addContact contact)
                          (.agreeToTermsOfService)
                          (.useKeyPair keypair))]
    (if with-login
      (.createLogin account-builder session)
      (.create account-builder session))))

(defn read [session keypair]
  (let [account-builder (doto (AccountBuilder.)
                          (.onlyExisting)
                          (.useKeyPair keypair))]
    (.create account-builder session)))

(def restore read)

(defn login [account-path keypair session]
  (Login. (load-url account-path) keypair session))

(extend-type Account
  Certificaat
  (marshal [this path]
    (spit path (.getLocation this))))
