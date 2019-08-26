(ns certificaat.plugins.server
  (:require
   [certificaat.kung-fu :as k]
   [immutant.web :refer [run stop]]
   [clojure.string :as str]
   [clojure.java.io :as io]
   [clojure.tools.logging :as log]))

(def stop-server stop )

(def handler
  (fn [challenges request]
    (loop [xs challenges]
      (if (= (:uri request) (str "/.well-known/acme-challenge/" (.getToken (first xs))))
        (log/spyf "OK %s" {:status 200
                           :headers {"Content-Type" "text/plain"}
                           :body (.getAuthorization (first xs))})
        (recur (rest xs))))))

(defn start-server [handler port]
  (let [server (run handler {:port port})]
    server))

(defn listen [challenges {{{port :port enabled :enabled} :httpd} :plugins :as options}]
  (when enabled
    (let [handler (partial handler challenges)]
      (start-server handler port))))

#_ (defn listen [{{{enabled :enabled} :httpd} :plugins config-dir :config-dir domain :domain :as options}]
  (let [session (k/session options)
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file (str config-dir domain))))]
    (when enabled
      (let [handler (partial handler "challenge")]
        (start-server handler)))))


