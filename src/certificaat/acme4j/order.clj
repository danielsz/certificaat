(ns certificaat.acme4j.order
  (:require [certificaat.domain :refer [Certificaat]]
            [clojure.tools.logging :as log])
  (:import [org.shredzone.acme4j Order]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeProtocolException]))


(defn create [account]
  (let [order-builder (.newOrder account)]
    (.create order-builder)))

(extend-type Order
  Certificaat
  (valid? [this]
    (let [status (try
                   (.getStatus this)
                   (catch AcmeProtocolException e (log/warn (.getMessage e))))]
      (log/debug "Order status:" status)
      (= Status/VALID status))))
