use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'WebService::RTMAgent',
    AUTHOR              => 'Yves Rutschle <cpan@rutschle.net>',
    VERSION_FROM        => 'lib/WebService/RTMAgent.pm',
    ABSTRACT_FROM       => 'lib/WebService/RTMAgent.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'WebService-RTMAgent-*' },
);
