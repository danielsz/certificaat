(ns certificaat.challenge
  (:refer-clojure :exclude [find])
  (:require [clojure.core.async :as a :refer [<! <!! >!! chan thread go-loop]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]])
  (:import [org.shredzone.acme4j.challenge Challenge Http01Challenge Dns01Challenge TlsSni01Challenge TlsSni02Challenge OutOfBand01Challenge]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeRetryAfterException]))

(defn http [challenge domain]
  (println "Please create a file in your web server's base directory.")
  (println "It must be reachable at:" (str "http://" domain  "/.well-known/acme-challenge/" (.getToken challenge)))
  (println "File name:" (.getToken challenge))
  (println "Content:" (.getAuthorization challenge))
  (println "The file must not contain any leading or trailing whitespaces or line breaks!")
  challenge)

(defn dns [challenge domain]
  (println "Please create a TXT record:")
  (println (str "_acme-challenge." domain " IN TXT " (.getDigest challenge)))
  challenge)

(defn display [challenge domain]
  (case (.getType challenge)
    "dns-01" (dns challenge domain)
    "http-01" (http challenge domain)))

(defn find [auth challenges]
  (.findCombination auth (into-array String challenges)))

(defn accept [challenge]
  (.trigger challenge)
  (let [c (chan)]
    (a/thread (loop [y 1
                     ms nil]
                (<!! (a/timeout (or ms 5000)))
                (log/info "Retrieving status, attempt" y)
                (let [status (log/spyf "status %s" (.getStatus challenge))]
                  (if (or (= status Status/VALID) (= status Status/INVALID) (> y 10))
                    status
                    (recur (inc y) (try
                                     (.update challenge)
                                     (catch AcmeRetryAfterException e
                                       (log/error (.getMessage e))
                                       (.getRetryAfter e))))))))))

#_ (defn restore []
     (Challenge/bind session (.getLocation challenge)))
