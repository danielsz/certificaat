(ns certificaat.plugins.webroot
  (:require [certificaat.acme4j.challenge :as challenge]
            [certificaat.kung-fu :as k]
            [clojure.java.io :as io]
            [clojure.string :as str])
  (:import java.net.URI))

(defn webroot [{config-dir :config-dir domain :domain {{path :path} :webroot} :plugins  :as options}]
  (let [session (k/session options) 
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))]
    (doseq [frozen-challenge frozen-challenges
          :let [uri (new URI (slurp frozen-challenge))
                challenge (challenge/restore session uri)
                file (io/file (str path "/.well-known/acme-challenge/" (.getToken challenge)))]
          :when (= (.getType challenge) "http-01")]
      (io/make-parents file)
      (spit file (.getAuthorization challenge))
      (println "Challenge data written to " (str file)))))
