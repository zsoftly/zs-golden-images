if length == 3
   and (map(.phase) == ["configure", "harden", "cleanup"])
   and all(.[]; .status == "completed" and .profile == $profile
       and .target == $target and .metadata_sha256 == $sha)
then .
else error("Build phase evidence is incomplete or belongs to another build")
end
