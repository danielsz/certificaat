(ns certificaat.acme4j.order
  (:require [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url exit]]
            [clojure.core.async :as a :refer [<! <!! >!! chan thread go-loop]]
            [clojure.tools.logging :as log]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j Order]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeException AcmeRetryAfterException AcmeServerException AcmeProtocolException]
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
  (processing? [this]
    (log/debug "Order status:" (.getStatus this))
    (= Status/PROCESSING (.getStatus this)))
  (invalid? [this]
    (log/debug "Order status:" (.getStatus this))
    (= Status/INVALID (.getStatus this)))
  (marshal [this path]
    (spit path (.getLocation this))))

(defn ready-to-finalize? [order]
  (let [c (chan)]
    (a/thread (loop [y 1
                     ms nil]
                (<!! (a/timeout (or ms 15000)))
                (log/debug "Retrieving order status, attempt" y ms)
                (cond
                  (d/ready? order) (do (log/debug "Order is ready")
                                       true)
                  (d/invalid? order) (exit 1 "Order is invalid")
                  (> y 10) (exit 1 "Too many attempts ")
                  :else (recur (inc y) (try
                                         (.update order)
                                         (catch AcmeRetryAfterException e
                                           (log/error (.getMessage e))
                                           (.getRetryAfter e)))))))))
