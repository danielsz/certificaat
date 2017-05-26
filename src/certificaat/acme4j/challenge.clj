(ns certificaat.acme4j.challenge
  (:refer-clojure :exclude [find])
  (:require [clojure.core.async :as a :refer [<! <!! >!! chan thread go-loop]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [clojure.string :as str])
  (:import [org.shredzone.acme4j.challenge Challenge Http01Challenge Dns01Challenge TlsSni01Challenge TlsSni02Challenge OutOfBand01Challenge]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeRetryAfterException AcmeServerException]))

(defn http [challenge domain]
  (->> ["Please create a file in your web server's base directory."
        (str  "It must be reachable at:" (str "http://" domain  "/.well-known/acme-challenge/" (.getToken challenge)))
        (str "File name:" (.getToken challenge))
        (str "Content:" (.getAuthorization challenge))
        "The file must not contain any leading or trailing whitespaces or line breaks!"]
       (str/join \newline)))

(defn dns [challenge domain]
  (->> ["Please create a TXT record in your DNS settings:"
       (str "_acme-challenge." domain " IN TXT " (.getDigest challenge))]
      (str/join \newline)))

(defn explain [challenge domain]
  (case (.getType challenge)
    "dns-01" (dns challenge domain)
    "http-01" (http challenge domain)))

(defn find [auth challenges]
  (.findCombination auth (into-array String challenges)))

(defn accept [challenge]
  (try (.trigger challenge)
       (catch AcmeServerException e
         (log/error "Please authorize again.")
         (throw e)))
  (let [c (chan)]
    (a/thread (loop [y 1
                     ms nil]
                (<!! (a/timeout (or ms 5000)))
                (log/info "Retrieving challenge status, attempt" y)
                (let [status (log/spyf "status %s" (.getStatus challenge))]
                  (if (or (= status Status/VALID) (= status Status/INVALID) (> y 10))
                    status
                    (recur (inc y) (try
                                     (.update challenge)
                                     (catch AcmeRetryAfterException e
                                       (log/error (.getMessage e))
                                       (.getRetryAfter e))))))))))
(defn restore [session uri]
  (Challenge/bind session uri))
