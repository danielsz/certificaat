(ns certificaat.kung-fu-test
  (:require [certificaat.kung-fu :as sut]
            [clojure.test :refer [deftest is]]))

(deftest addition
  (is (= 4 (+ 2 2)))
  (is (= 7 (+ 3 4))))
