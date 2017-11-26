(ns certificaat.plugins.server
  (:require
   [certificaat.kung-fu :as k]
   [immutant.web :refer [run stop]]
   [clojure.string :as str]
   [clojure.java.io :as io]))

(def handler
  (fn [content request]
    {:status 200
     :headers {"Content-Type" "text/plain"}
     :body content}))

(defn start-server [handler]
  (let [server (run handler {:port 3010})]
    server))

(defn listen [{{{enabled :enabled} :httpd} :plugins config-dir :config-dir domain :domain :as options}]
  (let [session (k/session options) 
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))]
    (when enabled
      (let [handler (partial handler "challenge")]
        (start-server handler)))))
