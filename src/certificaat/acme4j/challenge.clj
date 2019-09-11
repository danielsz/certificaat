(ns certificaat.acme4j.challenge
  (:refer-clojure :exclude [find])
  (:require [clojure.core.async :as a :refer [<! <!! >!! chan thread go-loop]]
            [clojure.tools.logging :as log]
            [environ.core :refer [env]]
            [certificaat.domain :as d :refer [Certificaat]]
            [certificaat.utils :refer [load-url]]
            [clojure.string :as str])
  (:import [org.shredzone.acme4j.challenge Challenge Http01Challenge Dns01Challenge TlsAlpn01Challenge]
           [org.shredzone.acme4j Status]
           [org.shredzone.acme4j.exception AcmeException AcmeRetryAfterException AcmeServerException AcmeProtocolException]))

(defn tls-alpn-01 [challenge domain]
  (->> ["With the tls-alpn-01 challenge, you prove to the CA that you are able to control the web server of the domain to be authorized, by letting it respond to a request with a specific self-signed cert utilizing the ALPN extension."
      "You need to create a self-signed certificate with the domain to be validated set as the only Subject Alternative Name. The acmeValidation must be set as DER encoded OCTET STRING extension with the object id 1.3.6.1.5.5.7.1.31. It is required to set this extension as critical."
      "After that, configure your web server so it will use this certificate on a SNI request to the subject."
       (str/join \newline)]))

(defn http-01 [challenge domain]
  (->> ["With the http-01 challenge, you prove to the CA that you are able to control the web site content of the domain to be authorized, by making a file with a signed content available at a given path."
      "Please create a file in your web server's base directory."
      (str "It must be reachable at: " (str "http://" domain  "/.well-known/acme-challenge/" (.getToken challenge)))
        (str "File name: " (.getToken challenge))
        (str "Content: " (.getAuthorization challenge))
        "The file must not contain any leading or trailing whitespaces or line breaks!"
        "The Content-Type header must be either text/plain or absent"
        "The request is sent to port 80 only. There is no way to choose a different port, for security reasons."
        "The challenge is completed when the CA was able to download that file and found content in it."]
       (str/join \newline)))

(defn dns-01 [challenge domain]
  (->> ["With the dns-01 challenge, you prove to the CA that you are able to control the DNS records of the domain to be authorized, by creating a TXT record with a signed content."
      "Please create a TXT record in your DNS settings:"
      (str "_acme-challenge." domain " IN TXT " (.getDigest challenge))
        "The challenge is completed when the CA was able to fetch the TXT record and got the correct digest returned."]
      (str/join \newline)))

(defn explain [challenge domain]
  (case (.getType challenge)
    "dns-01" (dns-01 challenge domain)
    "http-01" (http-01 challenge domain)
    "tls-alpn-01" (tls-alpn-01 challenge domain) ))

(def enums {"dns-01" Dns01Challenge/TYPE
            "http-01" Http01Challenge/TYPE
            "tls-alpn-01" TlsAlpn01Challenge/TYPE})

(defn find [auth type]
  (.findChallenge auth (get enums type)))

(extend-type Challenge
  Certificaat
  (valid? [this]
    (log/debug "Challenge status:" (.getStatus this))
    (= Status/VALID (.getStatus this)))
  (processing? [this]
    (log/debug "Challenge status:" (.getStatus this))
    (= Status/PROCESSING (.getStatus this)))
  (invalid? [this]
    (log/debug "Challenge status:" (.getStatus this))
    (= Status/INVALID (.getStatus this)))
  (pending? [this]
    (log/debug "Challenge status:" (.getStatus this))
    (= Status/PENDING (.getStatus this)))
  (marshal [this path]
    (spit path (.getLocation this))))

(defn accept [challenge]
  (log/debug "Triggering challenge" (.getType challenge))
  (try (.trigger challenge)
       (catch AcmeException e
         (throw e)))
  (let [c (chan)]
    (a/thread (loop [y 1
                     ms nil]
                (<!! (a/timeout (or ms 5000)))
                (log/debug "Retrieving challenge status, attempt" y ms)
                (cond
                  (d/valid? challenge) (str "Valid after" y "attempts")
                  (d/invalid? challenge) (do (log/error (.getError challenge))
                                             "Invalid after" y "attempts")
                  (> y 10) "Too many attempts"
                  (or (d/processing? challenge) (d/pending? challenge)) (recur (inc y) (try
                                                                                         (.update challenge)
                                                                                         (catch AcmeRetryAfterException e
                                                                                           (log/error (.getMessage e))
                                                                                           (.getRetryAfter e)))))))))



