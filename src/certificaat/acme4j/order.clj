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
    (log/debug "Order status:" (.getStatus this))
    (= Status/VALID (.getStatus this)))
  (pending? [this]
    (log/debug "Order status:" (.getStatus this))
    (= Status/PENDING (.getStatus this)))
  (ready? [this]
    (log/debug "Order status:" (.getStatus this))
    (= Status/READY (.getStatus this)))
  (processus? [this]
    (log/debug "Order status:" (.getStatus this))
    (= Status/PROCESSING (.getStatus this)))
  (invalid? [this]
    (log/debug "Order status:" (.getStatus this))
    (= Status/INVALID (.getStatus this)))
  (marshal [this path]
    (spit path (.getLocation this))))
