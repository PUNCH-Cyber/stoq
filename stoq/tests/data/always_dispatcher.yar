rule always_dummy
{
    meta:
        plugin = "dummy_worker"
    condition:
       true
}


rule always_nothing
{
    condition:
       true
}
