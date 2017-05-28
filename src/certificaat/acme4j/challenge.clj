(ns certificaat.acme4j.challenge
  (:refer-clojure :exclude [find])
  (:require [clojure.core.async :as a :refer [<! <!! >!! chan thread go-loop]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [clojure.string :as str])
  (:import [org.shredzone.acme4j.challenge Challenge Http01Challenge Dns01Challenge TlsSni01Challenge TlsSni02Challenge OutOfBand01Challenge]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeRetryAfterException AcmeServerException]))

(defn tls-sni-01 [challenge domain]
  (->> ["With the tls-sni-01 challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a SNI request with a specific self-signed cert."
        (str "You need to create a self-signed certificate with " (.getSubject challenge) " set as Subject Alternative Name.")
        "After that, configure your web server so it will use this certificate on a SNI request to the subject."
        "The challenge is completed when the CA was able to send the SNI request and get the correct certificate in return."
        "More information at https://github.com/shred/acme4j/blob/608dbb6fb97d248ae20733289bfc8773e1f83ea4/src/site/markdown/challenge/tls-sni-01.md"]
       (str/join \newline)))

(defn tls-sni-02 [challenge domain]
  (->> ["With the tls-sni-02 challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a SNI request with a specific self-signed cert." 
        (str "You need to create a self-signed certificate with both " (.getSubject challenge) " and " (.getSanB challenge) " set as Subject Alternative Name.")
        "After that, configure your web server so it will use this certificate on a SNI request to the subject."
        "The challenge is completed when the CA was able to send the SNI request and get the correct certificate in return."
        "More information at https://github.com/shred/acme4j/blob/608dbb6fb97d248ae20733289bfc8773e1f83ea4/src/site/markdown/challenge/tls-sni-02.md"]
       (str/join \newline)))

(defn oob-01 [challenge domain]
  (->> ["The oob-01 challenge is an out of band challenge that is used when there is no automatic way of validating ownership of a domain. The client is instead required to perform actions outside of the ACME protocol." 
        (str "You need to go to  " (.getValidationUrl challenge) " to receive further instructions about the actions to be taken")
        "The challenge must be triggered before the URL is opened in a browser."
        "Due to the nature of this challenge, it may take a considerable amount of time until its state changes to VALID."]
       (str/join \newline)))

(defn http-01 [challenge domain]
  (->> ["Please create a file in your web server's base directory."
        (str  "It must be reachable at:" (str "http://" domain  "/.well-known/acme-challenge/" (.getToken challenge)))
        (str "File name: " (.getToken challenge))
        (str "Content: " (.getAuthorization challenge))
        "The file must not contain any leading or trailing whitespaces or line breaks!"
        "The Content-Type header must be either text/plain or absent"
        "The request is sent to port 80 only. There is no way to choose a different port, for security reasons."
        "The challenge is completed when the CA was able to download that file and found content in it."]
       (str/join \newline)))

(defn dns-01 [challenge domain]
  (->> ["Please create a TXT record in your DNS settings:"
        (str "_acme-challenge." domain " IN TXT " (.getDigest challenge))
        "The challenge is completed when the CA was able to fetch the TXT record and got the correct digest returned."]
      (str/join \newline)))

(defn explain [challenge domain]
  (case (.getType challenge)
    "dns-01" (dns-01 challenge domain)
    "http-01" (http-01 challenge domain)
    "tls-sni-01" (tls-sni-01 challenge domain)
    "tls-sni-02" (tls-sni-02 challenge domain)
    "oob-01" (oob-01 challenge domain)))

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
