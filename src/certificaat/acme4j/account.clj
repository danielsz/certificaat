(ns certificaat.acme4j.account
  (:refer-clojure :exclude [read])
  (:require [environ.core :refer [env]]
            [clojure.tools.logging :as log]
            [certificaat.acme4j.keypair :as keypair])
  (:import
   [org.shredzone.acme4j AccountBuilder]))

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

(defn restore [x y])
