(ns certificaat.kung-fu
  (:require [certificaat.util.configuration :as c]
            [certificaat.acme4j.authorization :as h]
            [certificaat.acme4j.session :as s]
            [certificaat.acme4j.challenge :as l]
            [certificaat.acme4j.account :as a]
            [certificaat.acme4j.registration :as r]
            [certificaat.acme4j.certificate :as t]))

(defn setup [{config-dir :config-dir key-type :key-type key-size :key-size keypair-filename :keypair-filename}]
  (let [keypair (a/keypair key-type key-size)
        domain-keypair (a/keypair key-type key-size)]
    (c/create-dir config-dir)
    (c/add-keypair config-dir keypair-filename keypair)
    (c/add-keypair config-dir (str domain "-keypair.pem") domain-keypair)))

(defn register [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri contact :contact}]
  (let [keypair (a/restore config-dir keypair-filename)
        registration (r/create keypair acme-uri contact)]
    (spit (str config-dir "registration.uri") (.getLocation registration))))

(defn authorize [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri domain :domain san :san challenges :challenges}]
  (let [keypair (a/restore config-dir keypair-filename)
        registration-uri (new URI (slurp (str config-dir "registration.uri")))
        session (s/create keypair acme-uri)
        reg (r/restore session registration-uri)
        domains (if san
                  (conj san domain)
                  [domain])]
    (doseq [domain domains
            :let [auth (h/create domain reg)
                  challenges (l/find auth challenges)]]                  
      (doseq [challenge challenges
              i (range (count challenges))
              :let [explanation (l/explain challenge domain)]]
        (println explanation)
        (spit (str config-dir "challenge." domain "." (.getType challenge) ".txt") explanation)
        (spit (str config-dir "challenge." domain "." i ".uri") (.getLocation challenge))))))

(defn challenge [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri}]
  (let [keypair (a/restore config-dir keypair-filename)
        session (s/create keypair acme-uri)
        frozen-challenges (filter (comp #(= (first %) "challenge") #(str/split % #"\.") #(.getName %)) (file-seq (io/file config-dir)))]
    (doseq [frozen-challenge frozen-challenges
                  :let [uri (new URI (slurp frozen-challenge))
                        challenge (l/restore session uri)]]
      (if (= Status/VALID (<!! (l/accept challenge)))
        (println "Well done, you've succcessfully associated your domain with your account. You can now retrieve your certificate.\n")
        (println "Sorry, something went wrong\n")))))


(defn request [{config-dir :config-dir keypair-filename :keypair-filename acme-uri :acme-uri domain :domain organisation :organisation san :san}]
  (let [keypair (a/restore config-dir keypair-filename)
        domain-keypair (a/restore config-dir (str domain "-keypair.pem"))
        registration-uri (new URI (slurp (str config-dir "registration.uri")))
        session (s/create keypair acme-uri)
        reg (r/restore session registration-uri)
        csrb (t/prepare domain-keypair domain organisation (when san san))
        cert (t/request csrb reg)]
    (t/persist-certificate-request csrb config-dir domain)
    (t/persist config-dir cert)))
