(ns certificaat.plugins.webroot
  (:require [certificaat.kung-fu :as k]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import [java.net URI]))

(defn webroot [{config-dir :config-dir domain :domain {{path :path enabled :enabled} :webroot} :plugins :as options}]
  (when enabled
    (let [challenges (k/get-challenges options)]
      (doseq [challenge challenges
              :let [file (io/file (str path "/" domain "/.well-known/acme-challenge/" (.getToken challenge)))]
              :when (= (.getType challenge) "http-01")]
        (io/make-parents file)
        (spit file (.getAuthorization challenge))
        (println "Challenge data written to " (str file))))))
