(ns certificaat.acme4j.order
  (:require [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url]]
            [clojure.tools.logging :as log]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j Order]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeProtocolException]
           [java.net URL]))


(defn create [account domains]
  (let [order-builder (doto (.newOrder account)
                        (.domains domains))]
    (.create order-builder)))

(defn restore [login path]
  (.bindOrder login (load-url path)))

(extend-type Order
  Certificaat
  (valid? [this]
    (let [status (try
                   (.getStatus this)
                   (catch AcmeProtocolException e (log/warn (.getMessage e))))]
      (log/debug "Order status:" status)
      (= Status/VALID status)))
  (pending? [this]
    (let [status (try
                   (.getStatus this)
                   (catch AcmeProtocolException e (log/warn (.getMessage e))))]
      (log/debug "Order status:" status)
      (= Status/PENDING status)))
  (marshal [this path]
    (spit path (.getLocation this))))
