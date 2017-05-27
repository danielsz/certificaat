(ns certificaat.util.authentication
  (:import [org.jvnet.libpam PAM PAMException UnixUser])
  (:require [clojure.string :as str]))

(defn authenticate [password]
  (let [username (System/getProperty "user.name")
        pam (PAM. "auth")]
    (.authenticate pam username password)))
          
(defn prompt []
  (let [console (System/console)
        password (.readPassword console "Please enter your password: " nil)]
    (str/join password)))

