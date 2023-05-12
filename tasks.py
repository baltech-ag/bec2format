from invoke import task


@task()
def unittest(c):
    c.run("python -m unittest")
