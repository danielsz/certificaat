(ns certificaat.acme4j.order
  (:require [certificaat.domain :refer [Certificaat]]
            [certificaat.utils :refer [load-url exit]]
            [clojure.core.async :as a :refer [<! <!! >!! chan thread go-loop]]
            [clojure.tools.logging :as log]
            [certificaat.domain :as d :refer [Certificaat]]
            [clojure.java.io :as io])
  (:import [org.shredzone.acme4j Order]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeException AcmeRetryAfterException AcmeServerException AcmeProtocolException AcmeRateLimitedException]
           [java.net URL]))


(defn create [account domains]
  (let [order-builder (doto (.newOrder account)
                        (.domains domains))]
    (try
      (.create order-builder)
      (catch AcmeRateLimitedException e
        (exit 1 (.getMessage e))))))

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
  (if (d/ready? order)
    (a/thread true)
    (a/thread (loop [y 1
                     ms nil]
                (log/debug "Retrieving order status, attempt" y ms)
                (<!! (a/timeout (or ms 5000)))
                (cond
                  (d/ready? order) (do (log/debug "Order is ready")
                                       true)
                  (d/invalid? order) (exit 1 "Order is invalid")
                  (> y 10) (exit 1 "Too many attempts finalizing order")
                  :else (recur (inc y) (try
                                         (.update order)
                                         (catch AcmeRetryAfterException e
                                           (log/error (.getMessage e))
                                           (.getRetryAfter e)))))))))
